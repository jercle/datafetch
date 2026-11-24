package parser

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jercle/datafetch/dmarcreporting/internal/model"
)

// Aggregate is one parsed RUA report and its rows.
type Aggregate struct {
	Report  *model.AggregateReport   `json:"report"`
	Records []*model.AggregateRecord `json:"records"`
}

// XML shape per RFC 7489 Appendix C; DMARCbis additions (np, testing,
// discovery_method, human_result, namespaced root) are tolerated - Go's
// decoder matches un-namespaced tags in any namespace.
type xmlFeedback struct {
	XMLName  xml.Name `xml:"feedback"`
	Version  string   `xml:"version"`
	Metadata struct {
		OrgName      string `xml:"org_name"`
		Email        string `xml:"email"`
		ExtraContact string `xml:"extra_contact_info"`
		ReportID     string `xml:"report_id"`
		DateRange    struct {
			Begin string `xml:"begin"`
			End   string `xml:"end"`
		} `xml:"date_range"`
		Errors []string `xml:"error"`
	} `xml:"report_metadata"`
	Policy struct {
		Domain  string `xml:"domain"`
		ADKIM   string `xml:"adkim"`
		ASPF    string `xml:"aspf"`
		P       string `xml:"p"`
		SP      string `xml:"sp"`
		NP      string `xml:"np"`
		Pct     string `xml:"pct"`
		Fo      string `xml:"fo"`
		Testing string `xml:"testing"`
	} `xml:"policy_published"`
	Records []struct {
		Row struct {
			SourceIP string `xml:"source_ip"`
			Count    string `xml:"count"`
			Policy   struct {
				Disposition string `xml:"disposition"`
				DKIM        string `xml:"dkim"`
				SPF         string `xml:"spf"`
				Reasons     []struct {
					Type    string `xml:"type"`
					Comment string `xml:"comment"`
				} `xml:"reason"`
			} `xml:"policy_evaluated"`
		} `xml:"row"`
		Identifiers struct {
			HeaderFrom   string `xml:"header_from"`
			EnvelopeFrom string `xml:"envelope_from"`
			EnvelopeTo   string `xml:"envelope_to"`
		} `xml:"identifiers"`
		AuthResults struct {
			DKIM []struct {
				Domain   string `xml:"domain"`
				Selector string `xml:"selector"`
				Result   string `xml:"result"`
			} `xml:"dkim"`
			SPF []struct {
				Domain string `xml:"domain"`
				Scope  string `xml:"scope"`
				Result string `xml:"result"`
			} `xml:"spf"`
		} `xml:"auth_results"`
	} `xml:"record"`
}

// charsetReader handles the encodings reporters actually use. Anything that is
// not UTF-8 is treated as Latin-1/Windows-1252 (byte → rune), which is lossless
// for the ASCII content that matters here.
func charsetReader(label string, r io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return r, nil
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for _, c := range b {
		out.WriteRune(rune(c))
	}
	return &out, nil
}

// parseAggregateXML parses one RUA XML document.
func parseAggregateXML(b []byte, filename string) (*Aggregate, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	// Some reporters wrap the report in a stray schema element or put junk
	// before it: start decoding at <feedback>, keeping the XML declaration
	// (it names the encoding).
	if i := bytes.Index(b, []byte("<feedback")); i > 0 {
		decl := []byte(nil)
		if j := bytes.Index(b[:i], []byte("?>")); j >= 0 && bytes.HasPrefix(bytes.TrimSpace(b), []byte("<?xml")) {
			decl = b[:j+2]
		}
		b = append(append([]byte{}, decl...), b[i:]...)
	}
	// Reports declared (or assumed) UTF-8 sometimes contain stray bytes.
	if head := bytes.ToLower(b[:min(len(b), 200)]); !utf8.Valid(b) &&
		(!bytes.Contains(head, []byte("encoding=")) || bytes.Contains(head, []byte("utf-8"))) {
		b = bytes.ToValidUTF8(b, []byte("?"))
	}
	var fb xmlFeedback
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.CharsetReader = charsetReader
	dec.Strict = false
	if err := dec.Decode(&fb); err != nil {
		return nil, fmt.Errorf("aggregate xml: %w", err)
	}
	md := fb.Metadata
	org := strings.TrimSpace(md.OrgName)
	rid := strings.TrimSpace(md.ReportID)
	dom := cleanDomain(fb.Policy.Domain)
	if rid == "" || (org == "" && md.Email == "") {
		return nil, fmt.Errorf("aggregate xml: missing report_id or org_name")
	}
	begin, end := unixTime(md.DateRange.Begin), unixTime(md.DateRange.End)

	email := strings.TrimSpace(md.Email)
	if !strings.Contains(email, "@") {
		email = parseAddr(email)
	}
	rep := &model.AggregateReport{
		ReportKey:      aggregateKey(org, rid, dom, md.DateRange.Begin, md.DateRange.End),
		ContentHash:    sha(b),
		Reporter:       model.Reporter{Email: strings.ToLower(email), Domain: domainOf(email)},
		OrgName:        org,
		ReportID:       rid,
		ExtraContact:   strings.TrimSpace(md.ExtraContact),
		Version:        strings.TrimSpace(fb.Version),
		DateBegin:      begin,
		DateEnd:        end,
		EventAt:        begin,
		ReportedDomain: dom,
		Policy: model.PolicyPublished{
			Domain: dom, ADKIM: lc(fb.Policy.ADKIM), ASPF: lc(fb.Policy.ASPF), P: lc(fb.Policy.P),
			SP: lc(fb.Policy.SP), NP: lc(fb.Policy.NP), Fo: strings.TrimSpace(fb.Policy.Fo), Testing: lc(fb.Policy.Testing),
		},
		Filename: filename,
	}
	if rep.Reporter.Domain == "" {
		rep.Reporter.Domain = cleanDomain(org) // many reporters use their domain as org_name
	}
	for _, e := range md.Errors {
		if e = strings.TrimSpace(e); e != "" {
			rep.Errors = append(rep.Errors, e)
		}
	}
	if pct, err := strconv.Atoi(strings.TrimSpace(fb.Policy.Pct)); err == nil {
		rep.Policy.Pct = &pct
	}

	agg := &Aggregate{Report: rep}
	ips := map[string]bool{}
	for i, rec := range fb.Records {
		count, _ := strconv.ParseInt(strings.TrimSpace(rec.Row.Count), 10, 64)
		r := &model.AggregateRecord{
			ReportKey: rep.ReportKey, Idx: i,
			OrgName: org, ReportID: rid, Reporter: rep.Reporter,
			ReportedDomain: dom, PolicyP: rep.Policy.P,
			DateBegin: begin, DateEnd: end, EventAt: begin,
			Count:        count,
			Disposition:  lc(rec.Row.Policy.Disposition),
			PolicyDKIM:   lc(rec.Row.Policy.DKIM),
			PolicySPF:    lc(rec.Row.Policy.SPF),
			HeaderFrom:   cleanDomain(rec.Identifiers.HeaderFrom),
			EnvelopeFrom: cleanDomain(rec.Identifiers.EnvelopeFrom),
			EnvelopeTo:   cleanDomain(rec.Identifiers.EnvelopeTo),
		}
		r.DMARCPass = r.PolicyDKIM == "pass" || r.PolicySPF == "pass"
		if ip, ok := parseIP(rec.Row.SourceIP); ok {
			r.Source.IP = ip.String()
			r.Source.IPVersion = 4
			if ip.Is6() {
				r.Source.IPVersion = 6
			}
			ips[r.Source.IP] = true
		}
		for _, rs := range rec.Row.Policy.Reasons {
			r.Reasons = append(r.Reasons, model.PolicyReason{Type: lc(rs.Type), Comment: strings.TrimSpace(rs.Comment)})
		}
		for _, d := range rec.AuthResults.DKIM {
			r.DKIM = append(r.DKIM, model.AggAuthResult{Domain: cleanDomain(d.Domain), Selector: strings.TrimSpace(d.Selector), Result: lc(d.Result)})
		}
		for _, s := range rec.AuthResults.SPF {
			r.SPF = append(r.SPF, model.AggAuthResult{Domain: cleanDomain(s.Domain), Scope: lc(s.Scope), Result: lc(s.Result)})
		}
		agg.Records = append(agg.Records, r)

		rep.Messages += count
		if r.DMARCPass {
			rep.DMARCPass += count
		}
		if r.PolicyDKIM == "pass" {
			rep.DKIMAligned += count
		}
		if r.PolicySPF == "pass" {
			rep.SPFAligned += count
		}
		switch r.Disposition {
		case "quarantine":
			rep.Quarantined += count
		case "reject":
			rep.Rejected += count
		}
	}
	rep.Records = len(agg.Records)
	rep.SourceIPs = len(ips)
	return agg, nil
}

func aggregateKey(org, rid, dom, begin, end string) string {
	return sha([]byte(strings.Join([]string{
		strings.ToLower(strings.TrimSpace(org)), strings.TrimSpace(rid), dom,
		strings.TrimSpace(begin), strings.TrimSpace(end),
	}, "\x00")))
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func lc(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func unixTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC()
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Unix(int64(f), 0).UTC()
	}
	if t := parseDate(s); t != nil {
		return *t
	}
	return time.Time{}
}

// isAggregateXML sniffs for an RUA <feedback> document (possibly namespaced).
func isAggregateXML(b []byte) bool {
	head := b[:min(len(b), 4096)]
	if !utf8.Valid(head[:min(len(head), 64)]) && !bytes.HasPrefix(head, []byte("\xef\xbb\xbf")) {
		return false
	}
	return bytes.Contains(head, []byte("<feedback")) &&
		(bytes.Contains(b[:min(len(b), 16384)], []byte("report_metadata")) || bytes.Contains(head, []byte("<?xml")))
}

// LooksLikeMessage is exported for the CLI's -parse mode.
func LooksLikeMessage(b []byte) bool { return looksLikeMessage(b) }

func (p *Parser) addAggregate(b []byte, filename string, res *Result) {
	agg, err := parseAggregateXML(b, filename)
	if err != nil {
		res.warn(err.Error())
		return
	}
	for _, have := range res.Aggregates { // same report attached twice in one mail
		if have.Report.ReportKey == agg.Report.ReportKey {
			return
		}
	}
	res.Aggregates = append(res.Aggregates, agg)
}
