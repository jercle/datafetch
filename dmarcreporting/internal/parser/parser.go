// Package parser extracts DMARC failure reports (RUF) from raw email.
//
// Handled shapes:
//   - RFC 6591 / RFC 5965 ARF: multipart/report; report-type=feedback-report
//     with a message/feedback-report part and the original as message/rfc822
//     or text/rfc822-headers.
//   - Reports attached to another email (.eml / message/rfc822, forwarded or
//     digested), including inside .zip / .gz attachments.
//   - ARF parts relabelled by a mail system on the way (Exchange turns them
//     into base64 "ATT00001" attachments, sometimes typed octet-stream or
//     text/plain): parts are recognised by content, not just by type.
//   - Non-ARF reporters that put "Feedback-Type: / Source-IP: ..." fields and
//     the original headers inline in a text or HTML body ("inline").
//   - Plain-text or HTML-table summaries with their own labels, such as the
//     Exim / SpamExperts "Sender Domain: / Sender IP Address:" format ("text").
//   - Bounces (DSNs) that say the message was refused because of DMARC, with
//     the refused message attached ("bounce").
//   - A failing message attached to a mail that says it is a DMARC failure,
//     with no fields at all ("headers").
//   - Aggregate (RUA) XML reports (.xml, .xml.gz, .zip, or bare XML parts) are
//     parsed into Aggregate values (see aggregate.go).
package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"net/mail"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jercle/datafetch/dmarcreporting/internal/model"
)

type Options struct {
	RedactSubject        bool
	StoreOriginalHeaders bool
	StoreRawFields       bool
	MaxReceived          int
}

type Parser struct{ opt Options }

func New(opt Options) *Parser {
	if opt.MaxReceived == 0 {
		opt.MaxReceived = 15
	}
	return &Parser{opt: opt}
}

// Result is everything found in one mailbox message.
type Result struct {
	Reports  []*model.FailureReport
	Warnings []string
	// Aggregates are the RUA reports found (deduplicated within the message).
	Aggregates []*Aggregate
	// Structure describes every MIME part seen and how it was classified. It
	// is stored with messages in which no report was found, for diagnosis.
	Structure []string
}

func (r *Result) warn(s string) { r.Warnings = append(r.Warnings, s) }

func (p *Parser) Parse(raw []byte) *Result {
	res := &Result{}
	p.parseMessage(raw, 0, res)
	return res
}

// ---------------------------------------------------------------- build

func (p *Parser) build(f Header, orig *Header, outer Header, format string, res *Result) *model.FailureReport {
	r := &model.FailureReport{Format: format}
	if orig == nil {
		empty := newHeader()
		orig = &empty
		if format == "arf" {
			r.Warnings = append(r.Warnings, "no original message/headers part")
		}
	}

	r.FeedbackType = strings.ToLower(f.Get("feedback-type"))
	if r.FeedbackType == "" && format != "arf" {
		r.FeedbackType = "auth-failure" // implied by reports that carry no ARF part
	}
	r.Version = f.Get("version")
	r.AuthFailure = splitList(f.Values("auth-failure"))
	r.DeliveryResult = strings.ToLower(f.Get("delivery-result"))
	r.IdentityAlignment = splitList(f.Values("identity-alignment"))
	if n, err := strconv.Atoi(f.Get("incidents")); err == nil {
		r.Incidents = n
	}
	r.ReportedDomain = cleanDomain(f.Get("reported-domain"))
	r.ReportedURI = f.Values("reported-uri")
	r.SPFDNS = f.Get("spf-dns")

	// Reporter = sender of the report message.
	if a := parseAddr(outer.Get("from")); a != "" {
		r.Reporter.Email = a
		r.Reporter.Domain = domainOf(a)
	}
	r.Reporter.ReportingMTA = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(f.Get("reporting-mta"), "dns;"), "dns ;"))
	r.Reporter.UserAgent = f.Get("user-agent")

	// Envelope.
	r.Envelope.MailFrom = strings.Trim(f.Get("original-mail-from"), "<> ")
	r.Envelope.MailFromDomain = domainOf(r.Envelope.MailFrom)
	for _, v := range f.Values("original-rcpt-to") {
		if v = strings.Trim(v, "<> "); v != "" {
			r.Envelope.RcptTo = append(r.Envelope.RcptTo, v)
		}
	}
	r.Envelope.EnvelopeID = f.Get("original-envelope-id")

	if f.Has("dkim-domain") || f.Has("dkim-selector") || f.Has("dkim-identity") {
		r.DKIM = &model.DKIMFields{
			Domain:   cleanDomain(f.Get("dkim-domain")),
			Selector: f.Get("dkim-selector"),
			Identity: f.Get("dkim-identity"),
		}
	}

	// Original message.
	o := &r.Original
	o.From = decodeWords(firstNonEmpty(orig.Get("from"), f.Get("original-from")))
	o.FromDomain = domainOf(parseAddr(o.From))
	for _, v := range orig.Values("to") {
		o.To = append(o.To, decodeWords(v))
	}
	o.ReplyTo = decodeWords(orig.Get("reply-to"))
	o.ReturnPath = strings.Trim(orig.Get("return-path"), "<> ")
	o.ReturnPathDomain = domainOf(o.ReturnPath)
	if p.opt.RedactSubject {
		if orig.Has("subject") || f.Has("original-subject") {
			o.Subject = "[redacted]"
		}
	} else {
		o.Subject = decodeWords(firstNonEmpty(orig.Get("subject"), f.Get("original-subject")))
	}
	o.MessageID = strings.Trim(firstNonEmpty(orig.Get("message-id"), f.Get("original-message-id")), "<> ")
	o.Date = parseDate(orig.Get("date"))
	o.XMailer = firstNonEmpty(orig.Get("x-mailer"), orig.Get("user-agent"))
	rec := orig.Values("received")
	if len(rec) > p.opt.MaxReceived {
		rec = rec[:p.opt.MaxReceived]
	}
	o.Received = rec
	for _, sig := range orig.Values("dkim-signature") {
		t := parseTagList(sig)
		if t["d"] != "" {
			o.DKIMSignatures = append(o.DKIMSignatures, model.DKIMFields{Domain: cleanDomain(t["d"]), Selector: t["s"], Identity: t["i"]})
		}
	}
	if p.opt.StoreOriginalHeaders {
		o.Headers = orig.Map()
	}

	// Authentication results: reporter's fields first, then original headers.
	arVals := append(append([]string{}, f.Values("authentication-results")...), orig.Values("authentication-results")...)
	r.AuthResults = buildAuthResults(arVals)

	// Fallbacks for the reported domain.
	if r.ReportedDomain == "" && r.AuthResults.DMARC != nil {
		r.ReportedDomain = cleanDomain(r.AuthResults.DMARC.HeaderFrom)
	}
	if r.ReportedDomain == "" {
		r.ReportedDomain = o.FromDomain
	}
	if r.Envelope.MailFromDomain == "" {
		if r.AuthResults.SPF != nil && r.AuthResults.SPF.MailFrom != "" {
			r.Envelope.MailFrom = r.AuthResults.SPF.MailFrom
			r.Envelope.MailFromDomain = domainOf(r.AuthResults.SPF.MailFrom)
		} else if o.ReturnPathDomain != "" {
			r.Envelope.MailFromDomain = o.ReturnPathDomain
		}
	}
	if len(r.AuthFailure) == 0 {
		r.AuthFailure = []string{"dmarc"} // required by RFC 6591 but often left out
	}
	// Plain-text reports state alignment as yes/no per mechanism.
	if len(r.IdentityAlignment) == 0 && (f.Has("spf-alignment") || f.Has("dkim-alignment")) {
		for _, m := range []string{"spf", "dkim"} {
			if isYes(f.Get(m + "-alignment")) {
				r.IdentityAlignment = append(r.IdentityAlignment, m)
			}
		}
		if len(r.IdentityAlignment) == 0 {
			r.IdentityAlignment = []string{"none"}
		}
	}
	if r.DeliveryResult == "" {
		r.DeliveryResult = dispositionOf(f.Get("dmarc-result"), f.Get("disposition"))
	}

	// Source IP: field, then Received-SPF client-ip, then top Received hop.
	if ip, ok := parseIP(f.Get("source-ip")); ok {
		r.Source.IP = ip.String()
	} else if ip, ok := ipFromReceivedSPF(orig.Values("received-spf")); ok {
		r.Source.IP, r.Source.Derived = ip.String(), true
	} else if ip, ok := ipFromReceived(orig.Values("received")); ok {
		r.Source.IP, r.Source.Derived = ip.String(), true
	}
	if r.Source.IP != "" {
		if a, err := netip.ParseAddr(r.Source.IP); err == nil {
			r.Source.IPVersion = 4
			if a.Is6() && !a.Is4In6() {
				r.Source.IPVersion = 6
			}
		}
	} else {
		r.Warnings = append(r.Warnings, "no source IP found")
	}

	// Times.
	r.ArrivalDate = parseDate(firstNonEmpty(f.Get("arrival-date"), f.Get("received-date")))
	switch {
	case r.ArrivalDate != nil:
		r.EventAt = *r.ArrivalDate
	case o.Date != nil:
		r.EventAt = *o.Date
	}
	if r.ReportedDomain == "" {
		r.Warnings = append(r.Warnings, "no reported domain found")
	}
	if p.opt.StoreRawFields && f.Len() > 0 {
		r.RawFields = f.Map()
	}
	r.Fingerprint = fingerprint(r, f)
	return r
}

func fingerprint(r *model.FailureReport, f Header) string {
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }
	write(r.Reporter.Domain)
	write(r.ReportedDomain)
	write(r.Source.IP)
	write(r.Original.MessageID)
	if r.Original.Date != nil {
		write(r.Original.Date.UTC().Format(time.RFC3339))
	}
	keys := make([]string, 0, len(f.order))
	keys = append(keys, f.order...)
	sort.Strings(keys)
	for _, k := range keys {
		write(k + "=" + strings.Join(f.m[k], "\x1f"))
	}
	if len(keys) == 0 {
		write(strings.Join(r.Original.Received, "\x1f"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------- helpers

func splitList(vals []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vals {
		for _, t := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			t = strings.ToLower(strings.TrimSpace(t))
			if t != "" && !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func cleanDomain(d string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".<>\"")
}

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-=*/!#$&'^` + "`" + `{|}~]*@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// parseAddr returns the bare address, tolerating redacted or broken headers.
func parseAddr(v string) string {
	v = decodeWords(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	if a, err := mail.ParseAddress(v); err == nil {
		return strings.ToLower(a.Address)
	}
	if m := emailRe.FindString(v); m != "" {
		return strings.ToLower(m)
	}
	return ""
}

func domainOf(addr string) string {
	addr = strings.Trim(addr, "<> ")
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return cleanDomain(addr[i+1:])
	}
	if strings.Contains(addr, ".") && !strings.ContainsAny(addr, " ") {
		return cleanDomain(addr) // header.i=@domain or bare domain
	}
	return ""
}

func parseIP(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "[]")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "IPv6:"), "ipv6:")
	if i := strings.IndexAny(s, " ;,"); i > 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

var (
	clientIPRe  = regexp.MustCompile(`(?i)client-ip=([0-9a-f:.]+)`)
	bracketIPRe = regexp.MustCompile(`\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]`)
	parenIPRe   = regexp.MustCompile(`\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)`)
)

func ipFromReceivedSPF(vals []string) (netip.Addr, bool) {
	for _, v := range vals {
		if m := clientIPRe.FindStringSubmatch(v); m != nil {
			if a, ok := parseIP(m[1]); ok {
				return a, true
			}
		}
	}
	return netip.Addr{}, false
}

// ipFromReceived returns the first public IP in the "from" clause of the
// top-most Received headers - the hop that handed the message to the reporter.
func ipFromReceived(vals []string) (netip.Addr, bool) {
	for _, v := range vals[:min(len(vals), 3)] {
		from := v
		if i := strings.Index(strings.ToLower(v), " by "); i > 0 {
			from = v[:i]
		}
		var cands []string
		for _, m := range bracketIPRe.FindAllStringSubmatch(from, -1) {
			cands = append(cands, m[1])
		}
		for _, m := range parenIPRe.FindAllStringSubmatch(from, -1) {
			cands = append(cands, m[1])
		}
		for _, c := range cands {
			if a, ok := parseIP(c); ok && a.IsGlobalUnicast() && !a.IsPrivate() {
				return a, true
			}
		}
	}
	return netip.Addr{}, false
}

var dateLayouts = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339, "2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05",
	"Mon, 2 Jan 2006 15:04:05 -0700 (MST)", "2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST",
	"Mon Jan 2 15:04:05 2006", "Mon Jan _2 15:04:05 MST 2006",
}

func parseDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if t, err := mail.ParseDate(s); err == nil {
		u := t.UTC()
		return &u
	}
	clean, _ := stripComments(s)
	clean = strings.Join(strings.Fields(clean), " ")
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, clean); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}
