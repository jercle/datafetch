package parser

import (
	"regexp"
	"strings"

	"github.com/jercle/datafetch/dmarcreporting/internal/model"
)

// arMethod is one "method=result ptype.prop=value ..." clause of an
// Authentication-Results header (RFC 8601).
type arMethod struct {
	method  string
	result  string
	props   map[string]string
	comment string
}

// splitTop splits on sep outside of (comments) and "quoted strings".
func splitTop(s string, sep byte) []string {
	var out []string
	depth, inQ, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
		case c == '"':
			inQ = !inQ
		case inQ:
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case c == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// stripComments removes (possibly nested) comments and returns them joined.
func stripComments(s string) (string, string) {
	var clean, com strings.Builder
	depth, inQ := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && depth == 0:
			inQ = !inQ
			clean.WriteByte(c)
		case inQ:
			clean.WriteByte(c)
		case c == '(':
			if depth > 0 {
				com.WriteByte(c)
			} else if com.Len() > 0 {
				com.WriteByte(' ')
			}
			depth++
		case c == ')' && depth > 0:
			depth--
			if depth > 0 {
				com.WriteByte(c)
			}
		case depth > 0:
			com.WriteByte(c)
		default:
			clean.WriteByte(c)
		}
	}
	return clean.String(), strings.TrimSpace(com.String())
}

func parseAuthResults(v string) []arMethod {
	var out []arMethod
	for i, seg := range splitTop(v, ';') {
		clean, comment := stripComments(seg)
		toks := strings.Fields(clean)
		if len(toks) == 0 {
			continue
		}
		if i == 0 && !strings.Contains(toks[0], "=") {
			continue // authserv-id [version]
		}
		k, val, ok := strings.Cut(toks[0], "=")
		if !ok {
			continue
		}
		m := arMethod{
			method:  strings.ToLower(strings.SplitN(k, "/", 2)[0]),
			result:  strings.ToLower(strings.Trim(val, `"`)),
			props:   map[string]string{},
			comment: comment,
		}
		for _, t := range toks[1:] {
			if pk, pv, ok := strings.Cut(t, "="); ok {
				m.props[strings.ToLower(pk)] = strings.Trim(pv, `"`)
			}
		}
		out = append(out, m)
	}
	return out
}

var (
	policyRe = regexp.MustCompile(`(?i)\bp=([a-z]+)`)
	disRe    = regexp.MustCompile(`(?i)\bdis=([a-z]+)`)
)

// buildAuthResults merges every Authentication-Results value we found. The
// first value for each method wins, so pass report fields before original
// headers (the reporter's own verdict is the authoritative one).
func buildAuthResults(values []string) model.AuthResults {
	var ar model.AuthResults
	seenDKIM := map[string]bool{}
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		ar.Raw = append(ar.Raw, v)
		for _, m := range parseAuthResults(v) {
			switch m.method {
			case "dmarc":
				if ar.DMARC != nil {
					continue
				}
				d := &model.DMARCResult{Result: m.result, HeaderFrom: strings.ToLower(m.props["header.from"])}
				if p := policyRe.FindStringSubmatch(m.comment); p != nil {
					d.Policy = strings.ToLower(p[1])
				}
				if p := disRe.FindStringSubmatch(m.comment); p != nil {
					d.Disposition = strings.ToLower(p[1])
				}
				ar.DMARC = d
			case "spf":
				if ar.SPF != nil {
					continue
				}
				ar.SPF = &model.SPFResult{Result: m.result, MailFrom: m.props["smtp.mailfrom"], Helo: m.props["smtp.helo"]}
			case "dkim":
				d := strings.ToLower(firstNonEmpty(m.props["header.d"], domainOf(m.props["header.i"])))
				s := m.props["header.s"]
				key := d + "|" + s + "|" + m.result
				if seenDKIM[key] {
					continue
				}
				seenDKIM[key] = true
				ar.DKIM = append(ar.DKIM, model.DKIMResult{Result: m.result, Domain: d, Selector: s})
			}
		}
	}
	return ar
}

// parseTagList parses DKIM-Signature style "k=v; k=v" lists.
func parseTagList(v string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(v, ";") {
		if k, val, ok := strings.Cut(part, "="); ok {
			out[strings.ToLower(strings.TrimSpace(k))] = strings.Join(strings.Fields(val), "")
		}
	}
	return out
}
