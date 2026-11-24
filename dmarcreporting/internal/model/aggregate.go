package model

import "time"

// AggregateReport is one RUA report (RFC 7489 Appendix C / DMARCbis), stored
// once per ReportKey. Its rows live in AggregateRecord documents.
type AggregateReport struct {
	// ReportKey = sha256(lower(org_name) | report_id | policy domain | begin | end).
	// report_id is unique per reporter (RFC 7489 §7.2.1.1), so this key is how
	// the same report delivered twice (several rua= addresses, re-sends,
	// re-processing) is recognised as a duplicate.
	ReportKey   string `bson:"reportKey" json:"reportKey"`
	ContentHash string `bson:"contentHash" json:"contentHash"`

	Reporter     Reporter `bson:"reporter" json:"reporter"`
	OrgName      string   `bson:"orgName" json:"orgName"`
	ReportID     string   `bson:"reportId" json:"reportId"`
	ExtraContact string   `bson:"extraContact,omitempty" json:"extraContact,omitempty"`
	Version      string   `bson:"version,omitempty" json:"version,omitempty"`
	Errors       []string `bson:"errors,omitempty" json:"errors,omitempty"`

	DateBegin time.Time `bson:"dateBegin" json:"dateBegin"`
	DateEnd   time.Time `bson:"dateEnd" json:"dateEnd"`
	// EventAt mirrors DateBegin so the dashboard's time filters work the same
	// way for failure and aggregate data.
	EventAt time.Time `bson:"eventAt" json:"eventAt"`

	ReportedDomain    string          `bson:"reportedDomain" json:"reportedDomain"`
	ReportedOrgDomain string          `bson:"reportedOrgDomain,omitempty" json:"reportedOrgDomain,omitempty"`
	Policy            PolicyPublished `bson:"policy" json:"policy"`

	Records     int   `bson:"records" json:"records"`
	Messages    int64 `bson:"messages" json:"messages"`
	DMARCPass   int64 `bson:"dmarcPass" json:"dmarcPass"`
	DKIMAligned int64 `bson:"dkimAligned" json:"dkimAligned"`
	SPFAligned  int64 `bson:"spfAligned" json:"spfAligned"`
	Quarantined int64 `bson:"quarantined" json:"quarantined"`
	Rejected    int64 `bson:"rejected" json:"rejected"`
	SourceIPs   int   `bson:"sourceIps" json:"sourceIps"`

	Filename   string     `bson:"filename,omitempty" json:"filename,omitempty"`
	ReceivedAt time.Time  `bson:"receivedAt" json:"receivedAt"`
	IngestedAt time.Time  `bson:"ingestedAt" json:"ingestedAt"`
	Mailbox    MailboxRef `bson:"mailbox" json:"mailbox"`
}

type PolicyPublished struct {
	Domain  string `bson:"domain,omitempty" json:"domain,omitempty"`
	ADKIM   string `bson:"adkim,omitempty" json:"adkim,omitempty"`
	ASPF    string `bson:"aspf,omitempty" json:"aspf,omitempty"`
	P       string `bson:"p,omitempty" json:"p,omitempty"`
	SP      string `bson:"sp,omitempty" json:"sp,omitempty"`
	NP      string `bson:"np,omitempty" json:"np,omitempty"`
	Pct     *int   `bson:"pct,omitempty" json:"pct,omitempty"`
	Fo      string `bson:"fo,omitempty" json:"fo,omitempty"`
	Testing string `bson:"testing,omitempty" json:"testing,omitempty"`
}

// AggregateRecord is one <record> row, denormalised with its report's
// metadata so the dashboard can aggregate without $lookup.
type AggregateRecord struct {
	ReportKey string `bson:"reportKey" json:"reportKey"`
	Idx       int    `bson:"idx" json:"idx"`

	OrgName           string    `bson:"orgName" json:"orgName"`
	ReportID          string    `bson:"reportId" json:"reportId"`
	Reporter          Reporter  `bson:"reporter" json:"reporter"`
	ReportedDomain    string    `bson:"reportedDomain" json:"reportedDomain"`
	ReportedOrgDomain string    `bson:"reportedOrgDomain,omitempty" json:"reportedOrgDomain,omitempty"`
	PolicyP           string    `bson:"policyP,omitempty" json:"policyP,omitempty"`
	DateBegin         time.Time `bson:"dateBegin" json:"dateBegin"`
	DateEnd           time.Time `bson:"dateEnd" json:"dateEnd"`
	EventAt           time.Time `bson:"eventAt" json:"eventAt"`

	Source Source `bson:"source" json:"source"`
	Count  int64  `bson:"count" json:"count"`

	Disposition string         `bson:"disposition,omitempty" json:"disposition,omitempty"`
	PolicyDKIM  string         `bson:"policyDkim,omitempty" json:"policyDkim,omitempty"` // aligned DKIM verdict
	PolicySPF   string         `bson:"policySpf,omitempty" json:"policySpf,omitempty"`   // aligned SPF verdict
	DMARCPass   bool           `bson:"dmarcPass" json:"dmarcPass"`
	Reasons     []PolicyReason `bson:"reasons,omitempty" json:"reasons,omitempty"`

	HeaderFrom      string          `bson:"headerFrom,omitempty" json:"headerFrom,omitempty"`
	HeaderFromOrg   string          `bson:"headerFromOrg,omitempty" json:"headerFromOrg,omitempty"`
	EnvelopeFrom    string          `bson:"envelopeFrom,omitempty" json:"envelopeFrom,omitempty"`
	EnvelopeTo      string          `bson:"envelopeTo,omitempty" json:"envelopeTo,omitempty"`
	EnvelopeFromOrg string          `bson:"envelopeFromOrg,omitempty" json:"envelopeFromOrg,omitempty"`
	DKIM            []AggAuthResult `bson:"dkim,omitempty" json:"dkim,omitempty"`
	SPF             []AggAuthResult `bson:"spf,omitempty" json:"spf,omitempty"`
}

type PolicyReason struct {
	Type    string `bson:"type,omitempty" json:"type,omitempty"`
	Comment string `bson:"comment,omitempty" json:"comment,omitempty"`
}

type AggAuthResult struct {
	Domain   string `bson:"domain,omitempty" json:"domain,omitempty"`
	Selector string `bson:"selector,omitempty" json:"selector,omitempty"`
	Scope    string `bson:"scope,omitempty" json:"scope,omitempty"`
	Result   string `bson:"result,omitempty" json:"result,omitempty"`
}
