package parser

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestARF(t *testing.T) {
	raw, err := os.ReadFile("testdata/arf.eml")
	if err != nil {
		t.Fatal(err)
	}
	res := New(Options{StoreRawFields: true}).Parse(raw)
	if len(res.Reports) != 1 {
		t.Fatalf("want 1 report, got %d (warnings %v)", len(res.Reports), res.Warnings)
	}
	r := res.Reports[0]
	check := map[string][2]string{
		"format":         {r.Format, "arf"},
		"feedbackType":   {r.FeedbackType, "auth-failure"},
		"reportedDomain": {r.ReportedDomain, "contoso.com.au"},
		"sourceIP":       {r.Source.IP, "203.0.113.45"},
		"reporter":       {r.Reporter.Domain, "reports.example.net"},
		"reportingMTA":   {r.Reporter.ReportingMTA, "mx1.example.net"},
		"mailFromDomain": {r.Envelope.MailFromDomain, "spoofy.example.org"},
		"fromDomain":     {r.Original.FromDomain, "contoso.com.au"},
		"subject":        {r.Original.Subject, "Urgent: invoice overdue"},
		"messageId":      {r.Original.MessageID, "fake-999@spoofy.example.org"},
		"delivery":       {r.DeliveryResult, "reject"},
		"dmarc":          {r.AuthResults.DMARC.Result, "fail"},
		"policy":         {r.AuthResults.DMARC.Policy, "reject"},
		"disposition":    {r.AuthResults.DMARC.Disposition, "reject"},
		"spf":            {r.AuthResults.SPF.Result, "fail"},
		"dkimSel":        {r.AuthResults.DKIM[0].Selector, "selector1"},
		"xmailer":        {r.Original.XMailer, "PHPMailer 6.0"},
		"sigDomain":      {r.Original.DKIMSignatures[0].Domain, "contoso.com.au"},
	}
	for k, v := range check {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", k, v[0], v[1])
		}
	}
	if r.ArrivalDate == nil || r.EventAt.IsZero() {
		t.Error("arrival date not parsed")
	}
	if r.Source.Derived {
		t.Error("source IP should come from Source-IP field")
	}
	if r.Fingerprint == "" {
		t.Error("no fingerprint")
	}
	// Same bytes -> same fingerprint (idempotent re-ingest).
	if New(Options{}).Parse(raw).Reports[0].Fingerprint != r.Fingerprint {
		t.Error("fingerprint not stable")
	}
}

const inlineReport = `From: postmaster@mail.example.com
To: dmarc@contoso.com.au
Subject: DMARC Failure Report for contoso.com.au
Content-Type: text/plain; charset=utf-8

A message claiming to be from you has failed the published DMARC policy.

Feedback-Type: auth-failure
Auth-Failure: spf, dkim
Source-IP: 198.51.100.7
Reported-Domain: contoso.com.au
Arrival-Date: 2026-11-15 22:10:00 +0000

Original headers:
Received: from bad.example (unknown [198.51.100.7]) by mail.example.com; Sun, 15 Nov 2026 22:10:00 +0000
From: CEO <ceo@contoso.com.au>
Subject: Gift cards
Message-ID: <x1@bad.example>
`

func TestInline(t *testing.T) {
	res := New(Options{}).Parse([]byte(inlineReport))
	if len(res.Reports) != 1 {
		t.Fatalf("want 1 report, got %d %v", len(res.Reports), res.Warnings)
	}
	r := res.Reports[0]
	if r.Format != "inline" || r.Source.IP != "198.51.100.7" || r.ReportedDomain != "contoso.com.au" {
		t.Errorf("unexpected: %+v", r)
	}
	if strings.Join(r.AuthFailure, ",") != "spf,dkim" {
		t.Errorf("authFailure = %v", r.AuthFailure)
	}
	if r.Original.Subject != "Gift cards" || r.Original.FromDomain != "contoso.com.au" {
		t.Errorf("original = %+v", r.Original)
	}
	if r.ArrivalDate == nil {
		t.Error("arrival date")
	}
}

// A report forwarded as a .eml inside a .zip, alongside an aggregate .xml.gz.
func TestZippedForwardedAndAggregate(t *testing.T) {
	arf, _ := os.ReadFile("testdata/arf.eml")
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("report1.eml")
	w.Write(arf)
	zw.Close()

	var gb bytes.Buffer
	gw := gzip.NewWriter(&gb)
	aggXML, _ := os.ReadFile("testdata/aggregate.xml")
	gw.Write(aggXML)
	gw.Close()

	msg := "From: admin@contoso.com.au\nSubject: Fwd: reports\nMIME-Version: 1.0\n" +
		"Content-Type: multipart/mixed; boundary=XX\n\n" +
		"--XX\nContent-Type: text/plain\n\nsee attached\n" +
		"--XX\nContent-Type: application/zip; name=reports.zip\nContent-Transfer-Encoding: base64\n\n" +
		base64.StdEncoding.EncodeToString(zb.Bytes()) + "\n" +
		"--XX\nContent-Type: application/gzip\nContent-Disposition: attachment; filename=agg.xml.gz\nContent-Transfer-Encoding: base64\n\n" +
		base64.StdEncoding.EncodeToString(gb.Bytes()) + "\n--XX--\n"

	res := New(Options{}).Parse([]byte(msg))
	if len(res.Reports) != 1 {
		t.Fatalf("want 1 report, got %d %v", len(res.Reports), res.Warnings)
	}
	if res.Reports[0].Reporter.Domain != "reports.example.net" {
		t.Errorf("reporter should be the nested report's sender, got %q", res.Reports[0].Reporter.Domain)
	}
	if len(res.Aggregates) != 1 {
		t.Errorf("aggregates = %d %v", len(res.Aggregates), res.Warnings)
	}
}

func TestNotAReport(t *testing.T) {
	res := New(Options{}).Parse([]byte("From: a@b.com\nSubject: hello\n\nJust a normal email.\nUser-Agent: foo\n"))
	if len(res.Reports) != 0 {
		t.Fatalf("expected no reports, got %d", len(res.Reports))
	}
}

func TestDerivedIP(t *testing.T) {
	msg := `From: r@rep.example
Subject: DMARC forensic report
Content-Type: multipart/report; report-type=feedback-report; boundary=b

--b
Content-Type: message/feedback-report

Feedback-Type: auth-failure
Auth-Failure: dmarc

--b
Content-Type: text/rfc822-headers

Received: from relay (relay.example [10.0.0.1]) by mx.rep.example; Mon, 16 Nov 2026 00:00:00 +0000
Received: from evil (evil.example [192.0.2.99]) by relay; Mon, 16 Nov 2026 00:00:00 +0000
Authentication-Results: mx.rep.example; dmarc=fail header.from=contoso.com.au
From: x@contoso.com.au
--b--
`
	res := New(Options{}).Parse([]byte(msg))
	if len(res.Reports) != 1 {
		t.Fatalf("got %d", len(res.Reports))
	}
	r := res.Reports[0]
	if r.Source.IP != "192.0.2.99" || !r.Source.Derived {
		t.Errorf("source = %+v", r.Source)
	}
	if r.ReportedDomain != "contoso.com.au" {
		t.Errorf("reportedDomain = %q", r.ReportedDomain)
	}
}

func TestAuthResultsComments(t *testing.T) {
	ar := buildAuthResults([]string{`mx.google.com; dkim=pass (test (nested)) header.i=@contoso.com.au header.s=s1; spf=softfail (google.com: domain of transitioning x@y.com) smtp.mailfrom=x@y.com; dmarc=fail (p=QUARANTINE sp=NONE dis=QUARANTINE) header.from=contoso.com.au`})
	if ar.DMARC.Policy != "quarantine" || ar.SPF.Result != "softfail" || ar.DKIM[0].Domain != "contoso.com.au" {
		t.Errorf("%+v %+v %+v", ar.DMARC, ar.SPF, ar.DKIM)
	}
}

func TestAggregate(t *testing.T) {
	xmlb, err := os.ReadFile("testdata/aggregate.xml")
	if err != nil {
		t.Fatal(err)
	}
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("google.com!contoso.com.au!1763164800!1763251199.xml")
	w.Write(xmlb)
	zw.Close()

	// The same report twice in one message (zip + plain xml) must yield one aggregate.
	msg := "From: noreply-dmarc-support@google.com\nSubject: Report domain: contoso.com.au\nMIME-Version: 1.0\n" +
		"Content-Type: multipart/mixed; boundary=YY\n\n" +
		"--YY\nContent-Type: application/octet-stream; name=r.zip\nContent-Transfer-Encoding: base64\n\n" +
		base64.StdEncoding.EncodeToString(zb.Bytes()) + "\n" +
		"--YY\nContent-Type: text/xml\n\n" + string(xmlb) + "\n--YY--\n"

	res := New(Options{}).Parse([]byte(msg))
	if len(res.Reports) != 0 || len(res.Aggregates) != 1 {
		t.Fatalf("reports=%d aggregates=%d warnings=%v", len(res.Reports), len(res.Aggregates), res.Warnings)
	}
	a := res.Aggregates[0]
	r := a.Report
	if r.OrgName != "google.com" || r.ReportID != "18123456789012345678" || r.ReportedDomain != "contoso.com.au" {
		t.Errorf("metadata %+v", r)
	}
	if r.Messages != 130 || r.DMARCPass != 120 || r.Quarantined != 7 || r.Records != 3 || r.SourceIPs != 3 {
		t.Errorf("totals messages=%d pass=%d quarantined=%d records=%d ips=%d", r.Messages, r.DMARCPass, r.Quarantined, r.Records, r.SourceIPs)
	}
	if r.Policy.P != "quarantine" || r.Policy.Pct == nil || *r.Policy.Pct != 100 || r.Policy.NP != "reject" {
		t.Errorf("policy %+v", r.Policy)
	}
	if r.DateBegin.Unix() != 1763164800 || r.Reporter.Domain != "google.com" {
		t.Errorf("date/reporter %v %q", r.DateBegin, r.Reporter.Domain)
	}
	rec := a.Records[2]
	if rec.Source.IP != "2001:db8::25" || rec.Source.IPVersion != 6 || rec.DMARCPass || rec.Reasons[0].Type != "forwarded" || rec.DKIM[0].Selector != "s2" {
		t.Errorf("record %+v", rec)
	}
	if a.Records[1].EnvelopeFrom != "spoofy.example.org" || a.Records[1].SPF[0].Result != "softfail" {
		t.Errorf("record 1 %+v", a.Records[1])
	}
	// Key ignores transport differences: re-parsing the bare XML gives the same key.
	b, _ := parseAggregateXML(xmlb, "")
	if b.Report.ReportKey != r.ReportKey {
		t.Error("report key not stable")
	}
}

func TestAggregateNamespacedLatin1(t *testing.T) {
	x := `<?xml version="1.0" encoding="windows-1252"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"><report_metadata><org_name>Exempl\xe9 Mail</org_name><email>dmarc@exemple.fr</email><report_id>abc</report_id><date_range><begin>1763164800</begin><end>1763251199</end></date_range></report_metadata><policy_published><domain>contoso.com.au</domain><p>reject</p></policy_published><record><row><source_ip>198.51.100.1</source_ip><count>2</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>contoso.com.au</header_from></identifiers></record></feedback>`
	x = strings.ReplaceAll(x, `\xe9`, "\xe9")
	a, err := parseAggregateXML([]byte(x), "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Report.OrgName != "Exemplé Mail" || a.Report.Rejected != 2 || a.Report.Reporter.Domain != "exemple.fr" {
		t.Errorf("%+v", a.Report)
	}
}

func one(t *testing.T, msg string) *Result {
	t.Helper()
	res := New(Options{StoreRawFields: true}).Parse([]byte(msg))
	if len(res.Reports) != 1 {
		t.Fatalf("want 1 report, got %d\nstructure:\n  %s\nwarnings: %v", len(res.Reports), strings.Join(res.Structure, "\n  "), res.Warnings)
	}
	return res
}

// Exchange hands ARF parts back as base64 "ATT0000n" attachments, and the
// declared type cannot be relied on: the parts must be recognised by content.
func TestRelabelledParts(t *testing.T) {
	fb := "Feedback-Type: auth-failure\r\nUser-Agent: X/1\r\nVersion: 1\r\nSource-IP: 203.0.113.45\r\n" +
		"Reported-Domain: contoso.com.au\r\nArrival-Date: Mon, 16 Nov 2026 00:58:12 +0000\r\n" +
		"Authentication-Results: mx; dmarc=fail (p=reject) header.from=contoso.com.au\r\n"
	hdrs := "Received: from evil (evil.example [203.0.113.45]) by mx; Mon, 16 Nov 2026 00:58:12 +0000\r\n" +
		"From: Pay <pay@contoso.com.au>\r\nSubject: Overdue\r\nMessage-ID: <a@evil.example>\r\n"
	for _, types := range [][2]string{
		{"message/feedback-report", "text/rfc822-headers"},
		{"application/octet-stream", "application/octet-stream"},
		{"text/plain", "text/plain"},
		{"application/octet-stream", "message/rfc822"},
	} {
		msg := "From: reporter@mx.example\r\nSubject: FW: Overdue\r\nMIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=\"_004_x\"\r\n\r\n" +
			"--_004_x\r\nContent-Type: text/plain; charset=\"us-ascii\"\r\n\r\nThis is an authentication failure report.\r\n\r\n" +
			"--_004_x\r\nContent-Type: " + types[0] + "; name=\"ATT00001\"\r\nContent-Disposition: attachment; filename=\"ATT00001\"\r\n" +
			"Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(fb)) + "\r\n\r\n" +
			"--_004_x\r\nContent-Type: " + types[1] + "; name=\"ATT00002\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
			base64.StdEncoding.EncodeToString([]byte(hdrs)) + "\r\n\r\n--_004_x--\r\n"
		if types[1] == "message/rfc822" { // embedded messages are not base64 encoded
			msg = strings.Replace(msg, "Content-Transfer-Encoding: base64\r\n\r\n"+base64.StdEncoding.EncodeToString([]byte(hdrs)), "\r\n"+hdrs+"\r\nbody", 1)
		}
		r := one(t, msg).Reports[0]
		if r.Format != "arf" || r.Source.IP != "203.0.113.45" || r.ReportedDomain != "contoso.com.au" ||
			r.Original.Subject != "Overdue" || r.AuthResults.DMARC == nil || r.AuthResults.DMARC.Policy != "reject" {
			t.Errorf("%v: %+v", types, r)
		}
	}
}

// A plain-text summary with its own labels and no ARF part.
func TestTextSummary(t *testing.T) {
	r := one(t, `From: no-reply@gateway.example.net
Subject: DMARC Forensic Report for contoso.com.au from IP 203.0.113.68
Content-Type: multipart/report; boundary="b"

--b
Content-Type: text/plain

A message using your domain did not pass the DMARC policy you publish.

  Sender Domain: contoso.com.au
  Sender IP Address: 203.0.113.68
  Received date: Mon, 07 Apr 2025 23:16:09 +0200
  SPF Alignment: no
  DKIM Alignment: no
  DMARC Results: Reject

------ A copy of the headers follows.

Received: from [203.0.113.68] (helo=x) by gateway.example.net; Mon, 07 Apr 2025 23:16:08 +0200
From: <user@contoso.com.au>
Subject: Payment from your account.
Message-Id: <1@contoso.com.au>
--b--
`).Reports[0]
	if r.Format != "text" || r.Source.IP != "203.0.113.68" || r.ReportedDomain != "contoso.com.au" ||
		r.Original.Subject != "Payment from your account." || r.DeliveryResult != "reject" ||
		strings.Join(r.IdentityAlignment, ",") != "none" || r.ArrivalDate == nil || r.FeedbackType != "auth-failure" {
		t.Errorf("%+v", r)
	}
}

func TestHTMLTable(t *testing.T) {
	r := one(t, `From: noreply@filter.example.net
Subject: DMARC failure notification
Content-Type: text/html

<html><body><p>A message failed DMARC evaluation.</p><table>
<tr><td>Source IP</td><td>203.0.113.9</td></tr>
<tr><th>Header From</th><td>billing@contoso.com.au</td></tr>
<tr><td>Subject</td><td>Invoice 4471</td></tr>
<tr><td>Disposition</td><td>quarantine</td></tr></table></body></html>
`).Reports[0]
	if r.Format != "text" || r.Source.IP != "203.0.113.9" || r.ReportedDomain != "contoso.com.au" ||
		r.Original.Subject != "Invoice 4471" || r.DeliveryResult != "quarantine" {
		t.Errorf("%+v", r)
	}
}

// A report forwarded inline, quoted with "> ".
func TestQuotedForward(t *testing.T) {
	r := one(t, "From: admin@contoso.com.au\nSubject: FW: report\nContent-Type: text/plain\n\nFYI\n\n"+
		"> Feedback-Type: auth-failure\n> Source-IP: 198.51.100.7\n> Reported-Domain: contoso.com.au\n>\n"+
		"> Received: from bad (bad.example [198.51.100.7]) by mx; Sun, 15 Nov 2026 22:10:00 +0000\n"+
		"> From: CEO <ceo@contoso.com.au>\n> Subject: Gift cards\n").Reports[0]
	if r.Format != "inline" || r.Source.IP != "198.51.100.7" || r.Original.Subject != "Gift cards" {
		t.Errorf("%+v", r)
	}
}

const bounce = `From: Mail Delivery Subsystem <mailer-daemon@mx.receiver.example>
Subject: Undeliverable: Your invoice
Content-Type: multipart/report; report-type=delivery-status; boundary="BB"

--BB
Content-Type: text/plain

Your message could not be delivered. REASON

--BB
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.receiver.example

Final-Recipient: rfc822; bob@receiver.example
Action: failed
Status: 5.7.1
Diagnostic-Code: smtp; 550 5.7.1 REASON

--BB
Content-Type: message/rfc822

Received: from app01.contoso.com.au (app01.contoso.com.au [192.0.2.44]) by mx.receiver.example; Mon, 16 Nov 2026 01:00:00 +0000
From: Accounts <accounts@contoso.com.au>
Subject: Your invoice
Message-ID: <inv-1@app01.contoso.com.au>

body
--BB--
`

func TestBounce(t *testing.T) {
	r := one(t, strings.ReplaceAll(bounce, "REASON", "rejected due to the domain's DMARC policy")).Reports[0]
	if r.Format != "bounce" || r.FeedbackType != "bounce" || r.Source.IP != "192.0.2.44" || r.ReportedDomain != "contoso.com.au" ||
		r.DeliveryResult != "reject" || r.Reporter.ReportingMTA != "mx.receiver.example" || r.Envelope.RcptTo[0] != "bob@receiver.example" {
		t.Errorf("%+v", r)
	}
	// An ordinary bounce (mailbox full) is not a DMARC failure.
	res := New(Options{}).Parse([]byte(strings.ReplaceAll(bounce, "REASON", "mailbox full")))
	if len(res.Reports) != 0 {
		t.Errorf("ordinary bounce produced %d reports", len(res.Reports))
	}
	if len(res.Structure) == 0 {
		t.Error("no structure recorded for an unparsed message")
	}
}

func TestAggregateQuirks(t *testing.T) {
	body := `<feedback><report_metadata><org_name>x.example</org_name><report_id>r1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata><policy_published><domain>contoso.com.au</domain></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>1</count></row></record></feedback>`
	for name, x := range map[string]string{
		"schema wrapper": `<?xml version="1.0"?> <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">` + "\n" + body + `</xs:schema>`,
		"invalid utf-8":  `<?xml version="1.0" encoding="UTF-8"?>` + strings.Replace(body, "x.example", "x\xff.example", 1),
		"no declaration": body,
	} {
		if !isAggregateXML([]byte(x)) {
			t.Errorf("%s: not detected", name)
			continue
		}
		if a, err := parseAggregateXML([]byte(x), ""); err != nil || a.Report.Messages != 1 {
			t.Errorf("%s: %v", name, err)
		}
	}
}
