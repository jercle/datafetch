package parser

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// found collects the interesting parts of one message.
type found struct {
	feedback  []entity // machine-readable ARF parts
	originals []entity // the failing message, or just its headers
	texts     []entity // human-readable bodies (html already converted)
	dsn       *entity  // message/delivery-status of a bounce
}

func (p *Parser) parseMessage(raw []byte, depth int, res *Result) int {
	if depth > maxDepth {
		res.warn("message nesting too deep")
		return 0
	}
	before := len(res.Reports)
	root := parseEntity(raw)
	var parts []entity
	leaves(root, depth, &parts, res.warn)

	var c found
	for _, e := range parts {
		p.classify(e, depth, res, &c)
	}

	subject := decodeWords(root.h.Get("subject"))
	switch {
	case len(c.feedback) > 0:
		origs := realOriginals(c.originals)
		for i, fb := range c.feedback {
			fields, _ := ParseHeaderBlock(fb.body)
			var orig *Header
			if i < len(origs) {
				orig = origs[i]
			} else if len(origs) == 1 {
				orig = origs[0]
			}
			if orig == nil {
				// Some reporters put the original headers in the text part.
				for _, t := range c.texts {
					if h := headersInText(t.body); h != nil {
						orig = h
						break
					}
				}
			}
			res.Reports = append(res.Reports, p.build(fields, orig, root.h, "arf", res))
		}

	case len(res.Reports) == before:
		// No ARF part. Look for the report in the text bodies: either ARF
		// field names, or a plain-text summary ("Sender IP Address: ...").
		origs := realOriginals(c.originals)
		for _, t := range c.texts {
			fields, orig, format := parseText(t.body, subject)
			if format == "" {
				continue
			}
			if orig == nil && len(origs) > 0 {
				orig = origs[0]
			}
			res.Reports = append(res.Reports, p.build(fields, orig, root.h, format, res))
			break // one report per message; other text parts are alternatives of the same body
		}
		// Nothing but the failing message itself (attached or quoted): accept
		// it when the mail says it is about an authentication failure.
		if len(res.Reports) == before && len(origs) > 0 && mentionsFailure(subject, c.texts, c.dsn) {
			fields, format := newHeader(), "headers"
			if c.dsn != nil {
				// A bounce: the receiver refused the message because of DMARC.
				fields, format = bounceFields(c.dsn.body), "bounce"
			}
			res.Reports = append(res.Reports, p.build(fields, origs[0], root.h, format, res))
		}
	}
	return len(res.Reports) - before
}

// classify decides what one MIME leaf is. The declared content type is only a
// hint: mail systems in the path (Exchange in particular) rename parts,
// re-encode them as base64 and relabel them as application/octet-stream or
// text/plain, so the content is sniffed as well.
func (p *Parser) classify(e entity, depth int, res *Result, c *found) {
	mt, ext := e.mediaType, e.ext()
	isText := strings.HasPrefix(mt, "text/")
	note := func(as string) {
		if len(res.Structure) < 60 {
			res.Structure = append(res.Structure, describe(e, depth, as))
		}
	}
	switch {
	case mt == "message/feedback-report":
		note("feedback report")
		c.feedback = append(c.feedback, e)

	case isAggregateXML(e.body):
		note("aggregate report")
		p.addAggregate(e.body, e.filename, res)

	case isArchive(e):
		files, _ := expandArchive(e)
		note(fmt.Sprintf("archive, %d file(s)", len(files)))
		for _, f := range files {
			p.classify(entity{h: newHeader(), mediaType: "application/octet-stream", filename: f.name, body: f.data}, depth+1, res, c)
		}

	case mt == "text/rfc822-headers" || mt == "message/rfc822-headers" || mt == "message/global-headers":
		note("original headers")
		c.originals = append(c.originals, e)

	case mt == "message/rfc822" || mt == "message/global" || ext == ".eml" || ext == ".msg" && looksLikeMessage(e.body):
		p.nestedOrOriginal(e, depth, res, c, note)

	case looksLikeFeedback(e.body):
		// A feedback report under another label (octet-stream, text/plain attachment, ...).
		note("feedback report (by content)")
		c.feedback = append(c.feedback, e)

	case mt == "message/delivery-status" || mt == "message/global-delivery-status":
		note("delivery status")
		c.dsn = &e

	case strings.HasPrefix(mt, "message/"):
		note("ignored") // disposition-notification, ...

	case isText:
		if mt == "text/html" || looksLikeHTML(e.body) {
			e.body = htmlToText(e.body)
		}
		note("text")
		c.texts = append(c.texts, e)

	case looksLikeMessage(e.body):
		p.nestedOrOriginal(e, depth, res, c, note)

	default:
		note("ignored")
	}
}

// nestedOrOriginal handles an embedded message: either a report that was
// forwarded as an attachment, or the failing message of the enclosing report.
func (p *Parser) nestedOrOriginal(e entity, depth int, res *Result, c *found, note func(string)) {
	aggBefore := len(res.Aggregates)
	if p.parseMessage(e.body, depth+1, res) > 0 || len(res.Aggregates) > aggBefore {
		note("attached message containing report(s)")
		return
	}
	note("original message")
	c.originals = append(c.originals, e)
}

func describe(e entity, depth int, as string) string {
	var b strings.Builder
	b.WriteString(strings.Repeat("  ", depth))
	b.WriteString(e.mediaType)
	if e.filename != "" {
		fmt.Fprintf(&b, " name=%q", e.filename)
	}
	if cte := strings.ToLower(e.h.Get("content-transfer-encoding")); cte != "" {
		b.WriteString(" " + cte)
	}
	fmt.Fprintf(&b, " %dB -> %s", len(e.body), as)
	// First line of content, which is what a part is recognised by.
	for _, l := range strings.Split(string(e.body[:min(len(e.body), 400)]), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if len(l) > 70 {
				l = l[:70] + "…"
			}
			if strings.ToValidUTF8(l, "") == l && !strings.ContainsFunc(l, func(r rune) bool { return r < 32 }) {
				fmt.Fprintf(&b, " | %s", l)
			}
			break
		}
	}
	return b.String()
}

func isArchive(e entity) bool {
	if len(e.body) >= 4 && (string(e.body[:4]) == "PK\x03\x04" || (e.body[0] == 0x1f && e.body[1] == 0x8b)) {
		return true
	}
	switch e.mediaType {
	case "application/zip", "application/x-zip-compressed", "application/gzip", "application/x-gzip":
		return true
	}
	return e.ext() == ".zip" || e.ext() == ".gz"
}

func looksLikeHTML(b []byte) bool {
	head := strings.ToLower(string(b[:min(len(b), 512)]))
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype html") || strings.Contains(head, "<table")
}

// realOriginals returns the header blocks of parts that really are a message
// (have a From, Received or Message-ID header), in order.
func realOriginals(parts []entity) []*Header {
	var out []*Header
	for _, e := range parts {
		h, _ := ParseHeaderBlock(e.body)
		if h.Has("from") || h.Has("received") || h.Has("message-id") || h.Has("return-path") {
			out = append(out, &h)
		}
	}
	return out
}

var failureRe = regexp.MustCompile(`(?i)dmarc|forensic|auth(entication)?[- ]failure|failure report|failed (the )?(spf|dkim)|(spf|dkim)[- ](check |authentication )?fail`)

// bounceFields turns a delivery-status part into report fields.
func bounceFields(dsn []byte) Header {
	f := newHeader()
	f.Add("feedback-type", "bounce")
	// A DSN has per-message fields, a blank line, then per-recipient fields.
	rest := dsn
	for len(rest) > 0 {
		var h Header
		h, rest = ParseHeaderBlock(rest)
		if h.Len() == 0 {
			break
		}
		for _, k := range []string{"reporting-mta", "remote-mta", "diagnostic-code", "status", "action", "arrival-date"} {
			if v := h.Get(k); v != "" && !f.Has(k) {
				f.Add(k, v)
			}
		}
		if v := h.Get("final-recipient"); v != "" {
			_, addr, _ := strings.Cut(v, ";")
			f.Add("original-rcpt-to", strings.TrimSpace(addr))
		}
	}
	if !f.Has("reporting-mta") && f.Has("remote-mta") {
		f.Add("reporting-mta", f.Get("remote-mta"))
	}
	if a := strings.ToLower(f.Get("action")); a == "failed" {
		f.Add("delivery-result", "reject")
	}
	return f
}

func mentionsFailure(subject string, texts []entity, dsn *entity) bool {
	if failureRe.MatchString(subject) || (dsn != nil && failureRe.Match(dsn.body)) {
		return true
	}
	for _, t := range texts {
		if failureRe.Match(t.body[:min(len(t.body), 8192)]) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- fields in text

// canonical maps a normalised label ("sender ip address") to the field name
// used by build(). ARF names are included, so "Source-IP:", "Source IP:" and
// "Sender IP Address:" all land on the same field.
var canonical = map[string]string{}

func init() {
	add := func(field string, labels ...string) {
		for _, l := range labels {
			canonical[l] = field
		}
	}
	for _, f := range []string{
		"feedback-type", "user-agent", "version", "original-mail-from", "original-rcpt-to", "original-envelope-id",
		"arrival-date", "reporting-mta", "source-ip", "incidents", "reported-domain", "reported-uri",
		"authentication-results", "auth-failure", "delivery-result", "dkim-domain", "dkim-identity", "dkim-selector",
		"dkim-canonicalized-header", "dkim-canonicalized-body", "spf-dns", "identity-alignment",
	} {
		add(f, strings.ReplaceAll(f, "-", " "))
	}
	add("arrival-date", "received date", "date received", "arrival time", "received time", "received at", "time received")
	add("source-ip", "sender ip address", "sender ip", "source ip address", "sending ip", "sending ip address",
		"client ip", "client ip address", "originating ip", "origin ip", "remote ip", "connecting ip", "ip address", "ip")
	add("reported-domain", "sender domain", "sending domain", "from domain", "header from domain", "header from",
		"policy domain", "dmarc domain", "domain")
	add("original-mail-from", "envelope from", "envelope sender", "mail from", "return path", "smtp mail from")
	add("original-rcpt-to", "envelope to", "rcpt to", "recipient", "recipients", "original recipient")
	add("original-from", "from", "from address", "header from address", "sender")
	add("original-subject", "subject")
	add("original-message-id", "message id")
	add("spf-alignment", "spf alignment", "spf aligned")
	add("dkim-alignment", "dkim alignment", "dkim aligned")
	add("dmarc-result", "dmarc results", "dmarc result", "dmarc")
	add("disposition", "disposition", "action", "action taken", "policy applied")
	add("spf-result", "spf", "spf result", "spf results")
	add("dkim-result", "dkim", "dkim result", "dkim results")
	add("policy", "policy", "dmarc policy", "published policy")
}

var (
	labelRe     = regexp.MustCompile(`^[ \t>*•·-]*([A-Za-z][A-Za-z0-9 ._/-]{0,40}?)[ \t]*[:=\t][ \t:=]*(\S.*)$`)
	origStartRe = regexp.MustCompile(`(?i)^[ \t>]*(Received|Return-Path|DKIM-Signature|Message-ID|ARC-Seal|X-Received|Delivered-To|Authentication-Results)\s*:`)
)

func normLabel(s string) string {
	s = strings.ToLower(strings.NewReplacer("-", " ", "_", " ", ".", " ", "/", " ").Replace(s))
	return strings.Join(strings.Fields(s), " ")
}

// arfOnly are labels that only an ARF report uses - seeing one is strong
// evidence, unlike generic words such as "subject" or "domain".
var arfOnly = map[string]bool{
	"feedback-type": true, "auth-failure": true, "source-ip": true, "reported-domain": true,
	"original-mail-from": true, "original-rcpt-to": true, "reporting-mta": true, "delivery-result": true,
	"identity-alignment": true, "dkim-domain": true, "arrival-date": true,
}

// looksLikeFeedback reports whether b is a machine-readable feedback report
// whatever it is labelled as: it starts with a header-style field and carries
// ARF fields. Prose that merely contains such fields does not qualify (its
// first line is not a field); parseText handles that.
func looksLikeFeedback(b []byte) bool {
	lines := strings.Split(string(normalizeNewlines(b[:min(len(b), 8192)])), "\n")
	seen, first := map[string]bool{}, true
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		k, _, ok := strings.Cut(l, ":")
		k = strings.TrimSpace(k)
		if first {
			if !ok || !isFieldName(k) {
				return false
			}
			first = false
		}
		if name := strings.ToLower(k); ok && arfOnly[name] {
			seen[name] = true
		}
	}
	return seen["feedback-type"] || (len(seen) >= 2 && (seen["source-ip"] || seen["reported-domain"] || seen["auth-failure"]))
}

// headersInText finds a block of original message headers quoted in a text body.
func headersInText(body []byte) *Header {
	lines := strings.Split(string(normalizeNewlines(body)), "\n")
	for i, l := range lines {
		if origStartRe.MatchString(l) {
			h, _ := ParseHeaderBlock([]byte(unquote(lines[i:])))
			if h.Len() >= 2 {
				return &h
			}
			return nil
		}
	}
	return nil
}

func unquote(lines []string) string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = strings.TrimPrefix(strings.TrimPrefix(l, "> "), ">")
	}
	return strings.Join(out, "\n")
}

// parseText extracts a report from a human-readable body. It returns the
// fields, any quoted original headers, and the format:
//
//	"inline"  ARF field names in the text (Feedback-Type / Auth-Failure ...)
//	"text"    a plain-text summary (Sender Domain / Sender IP Address ...)
//	""        not a report
func parseText(body []byte, subject string) (Header, *Header, string) {
	lines := strings.Split(string(normalizeNewlines(body)), "\n")
	end := len(lines)
	for i, l := range lines {
		if origStartRe.MatchString(l) {
			end = i
			break
		}
	}
	fields := newHeader()
	var lastKey, lastVal string
	flush := func() {
		// The first value wins, except for fields that legitimately repeat.
		if lastKey != "" && (!fields.Has(lastKey) || repeatable[lastKey]) {
			fields.Add(lastKey, lastVal)
		}
		lastKey, lastVal = "", ""
	}
	for _, l := range lines[:end] {
		if m := labelRe.FindStringSubmatch(l); m != nil {
			if field, ok := canonical[normLabel(m[1])]; ok {
				flush()
				lastKey, lastVal = field, strings.TrimSpace(m[2])
				continue
			}
		}
		// Folded continuation line of Authentication-Results.
		if lastKey == "authentication-results" && len(l) > 0 && (l[0] == ' ' || l[0] == '\t') && strings.TrimSpace(l) != "" {
			lastVal += " " + strings.TrimSpace(l)
			continue
		}
		flush()
	}
	flush()

	var orig *Header
	if end < len(lines) {
		h, _ := ParseHeaderBlock([]byte(unquote(lines[end:])))
		if h.Len() >= 2 {
			orig = &h
		}
	}

	// Values must be usable, or the label was a coincidence in prose.
	if v := fields.Get("source-ip"); v != "" {
		if ip, ok := ipIn(v); ok {
			fields.m["source-ip"] = []string{ip.String()}
		} else {
			fields.del("source-ip")
		}
	}
	if v := fields.Get("reported-domain"); v != "" {
		if d := domainIn(v); d != "" {
			fields.m["reported-domain"] = []string{d}
		} else {
			fields.del("reported-domain")
		}
	}

	hasIP := fields.Has("source-ip")
	hasDomain := fields.Has("reported-domain") || fields.Has("original-from") || fields.Has("original-mail-from") ||
		(orig != nil && orig.Has("from"))
	switch {
	case (fields.Has("feedback-type") || fields.Has("auth-failure")) && (hasIP || hasDomain || orig != nil):
		return fields, orig, "inline"
	case hasIP && hasDomain && (failureRe.MatchString(subject) || failureRe.Match(body[:min(len(body), 8192)])):
		return fields, orig, "text"
	}
	return Header{}, nil, ""
}

var repeatable = map[string]bool{"original-rcpt-to": true, "reported-uri": true, "authentication-results": true}

func (h *Header) del(k string) {
	delete(h.m, k)
	for i, o := range h.order {
		if o == k {
			h.order = append(h.order[:i], h.order[i+1:]...)
			return
		}
	}
}

var (
	ipTokenRe     = regexp.MustCompile(`[0-9A-Fa-f:.]{3,45}`)
	domainTokenRe = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\b`)
)

func ipIn(s string) (netip.Addr, bool) {
	for _, t := range ipTokenRe.FindAllString(s, 4) {
		if a, err := netip.ParseAddr(strings.Trim(t, ".:")); err == nil {
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func domainIn(s string) string {
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	m := domainTokenRe.FindString(s)
	if _, err := netip.ParseAddr(m); err == nil {
		return ""
	}
	return cleanDomain(m)
}

func isYes(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "y", "true", "pass", "passed", "aligned", "1":
		return true
	}
	return false
}

// dispositionOf reads the receiver's action out of free-text result fields
// such as "DMARC Results: None, Accept" or "Action: quarantine".
func dispositionOf(vals ...string) string {
	s := strings.ToLower(strings.Join(vals, " "))
	switch {
	case strings.Contains(s, "reject"):
		return "reject"
	case strings.Contains(s, "quarantine"), strings.Contains(s, "junk"), strings.Contains(s, "spam"):
		return "quarantine"
	case strings.Contains(s, "accept"), strings.Contains(s, "deliver"):
		return "delivered"
	}
	return ""
}
