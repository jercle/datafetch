// Package model holds the documents written to MongoDB. Field names (bson tags)
// are the contract with the dashboard module - change them in both places.
package model

import "time"

// FailureReport is one DMARC failure (forensic / RUF) report, normalised from
// RFC 5965 / RFC 6591 ARF, inline text bodies, or bare header dumps.
type FailureReport struct {
	Fingerprint string `bson:"fingerprint" json:"fingerprint"`

	// EventAt is the best-known time of the failing delivery: Arrival-Date if
	// the reporter supplied it, otherwise the original Date header, otherwise
	// when the report hit the mailbox. Every dashboard time filter uses it.
	EventAt     time.Time  `bson:"eventAt" json:"eventAt"`
	ArrivalDate *time.Time `bson:"arrivalDate,omitempty" json:"arrivalDate,omitempty"`
	ReceivedAt  time.Time  `bson:"receivedAt" json:"receivedAt"`
	IngestedAt  time.Time  `bson:"ingestedAt" json:"ingestedAt"`

	// Format is how the report was found: "arf" (feedback-report part),
	// "inline" (ARF fields in a text/html body), "text" (plain-text summary),
	// "bounce" (DSN refusing the message) or "headers" (failing message only).
	Format       string `bson:"format" json:"format"`
	FeedbackType string `bson:"feedbackType,omitempty" json:"feedbackType,omitempty"`
	Version      string `bson:"version,omitempty" json:"version,omitempty"`

	Reporter Reporter `bson:"reporter" json:"reporter"`

	ReportedDomain    string   `bson:"reportedDomain" json:"reportedDomain"`
	ReportedOrgDomain string   `bson:"reportedOrgDomain,omitempty" json:"reportedOrgDomain,omitempty"`
	ReportedURI       []string `bson:"reportedUri,omitempty" json:"reportedUri,omitempty"`

	AuthFailure       []string `bson:"authFailure,omitempty" json:"authFailure,omitempty"`
	DeliveryResult    string   `bson:"deliveryResult,omitempty" json:"deliveryResult,omitempty"`
	IdentityAlignment []string `bson:"identityAlignment,omitempty" json:"identityAlignment,omitempty"`
	Incidents         int      `bson:"incidents,omitempty" json:"incidents,omitempty"`

	Source   Source      `bson:"source" json:"source"`
	Envelope Envelope    `bson:"envelope" json:"envelope"`
	DKIM     *DKIMFields `bson:"dkim,omitempty" json:"dkim,omitempty"`
	SPFDNS   string      `bson:"spfDns,omitempty" json:"spfDns,omitempty"`

	AuthResults AuthResults `bson:"authResults" json:"authResults"`
	Original    Original    `bson:"original" json:"original"`
	Mailbox     MailboxRef  `bson:"mailbox" json:"mailbox"`

	RawFields map[string][]string `bson:"rawFields,omitempty" json:"rawFields,omitempty"`
	Warnings  []string            `bson:"warnings,omitempty" json:"warnings,omitempty"`
}

type Reporter struct {
	Email        string `bson:"email,omitempty" json:"email,omitempty"`
	Domain       string `bson:"domain,omitempty" json:"domain,omitempty"`
	OrgDomain    string `bson:"orgDomain,omitempty" json:"orgDomain,omitempty"`
	ReportingMTA string `bson:"reportingMta,omitempty" json:"reportingMta,omitempty"`
	UserAgent    string `bson:"userAgent,omitempty" json:"userAgent,omitempty"`
}

type Source struct {
	IP           string   `bson:"ip,omitempty" json:"ip,omitempty"`
	IPVersion    int      `bson:"ipVersion,omitempty" json:"ipVersion,omitempty"`
	Derived      bool     `bson:"derived,omitempty" json:"derived,omitempty"` // taken from Received/Received-SPF, not Source-IP
	IsPrivate    bool     `bson:"isPrivate,omitempty" json:"isPrivate,omitempty"`
	PTR          []string `bson:"ptr,omitempty" json:"ptr,omitempty"`
	PTRConfirmed bool     `bson:"ptrConfirmed,omitempty" json:"ptrConfirmed,omitempty"` // forward-confirmed rDNS
	PTROrgDomain string   `bson:"ptrOrgDomain,omitempty" json:"ptrOrgDomain,omitempty"`
	Geo          *Geo     `bson:"geo,omitempty" json:"geo,omitempty"`
	ASN          *ASN     `bson:"asn,omitempty" json:"asn,omitempty"`
}

type Geo struct {
	CountryCode    string   `bson:"countryCode,omitempty" json:"countryCode,omitempty"` // ISO 3166-1 alpha-2
	Country        string   `bson:"country,omitempty" json:"country,omitempty"`
	ContinentCode  string   `bson:"continentCode,omitempty" json:"continentCode,omitempty"`
	Region         string   `bson:"region,omitempty" json:"region,omitempty"`
	City           string   `bson:"city,omitempty" json:"city,omitempty"`
	PostalCode     string   `bson:"postalCode,omitempty" json:"postalCode,omitempty"`
	Lat            *float64 `bson:"lat,omitempty" json:"lat,omitempty"`
	Lon            *float64 `bson:"lon,omitempty" json:"lon,omitempty"`
	AccuracyRadius int      `bson:"accuracyRadiusKm,omitempty" json:"accuracyRadiusKm,omitempty"`
	TimeZone       string   `bson:"timeZone,omitempty" json:"timeZone,omitempty"`
	Provider       string   `bson:"provider,omitempty" json:"provider,omitempty"`
}

type ASN struct {
	Number int    `bson:"number,omitempty" json:"number,omitempty"`
	Org    string `bson:"org,omitempty" json:"org,omitempty"`
	Domain string `bson:"domain,omitempty" json:"domain,omitempty"`
}

type Envelope struct {
	MailFrom       string   `bson:"mailFrom,omitempty" json:"mailFrom,omitempty"`
	MailFromDomain string   `bson:"mailFromDomain,omitempty" json:"mailFromDomain,omitempty"`
	RcptTo         []string `bson:"rcptTo,omitempty" json:"rcptTo,omitempty"`
	EnvelopeID     string   `bson:"envelopeId,omitempty" json:"envelopeId,omitempty"`
}

type DKIMFields struct {
	Domain   string `bson:"domain,omitempty" json:"domain,omitempty"`
	Selector string `bson:"selector,omitempty" json:"selector,omitempty"`
	Identity string `bson:"identity,omitempty" json:"identity,omitempty"`
}

type AuthResults struct {
	Raw   []string     `bson:"raw,omitempty" json:"raw,omitempty"`
	DMARC *DMARCResult `bson:"dmarc,omitempty" json:"dmarc,omitempty"`
	SPF   *SPFResult   `bson:"spf,omitempty" json:"spf,omitempty"`
	DKIM  []DKIMResult `bson:"dkim,omitempty" json:"dkim,omitempty"`
}

type DMARCResult struct {
	Result      string `bson:"result,omitempty" json:"result,omitempty"`
	Policy      string `bson:"policy,omitempty" json:"policy,omitempty"`           // p= from the comment
	Disposition string `bson:"disposition,omitempty" json:"disposition,omitempty"` // dis= from the comment
	HeaderFrom  string `bson:"headerFrom,omitempty" json:"headerFrom,omitempty"`
}

type SPFResult struct {
	Result   string `bson:"result,omitempty" json:"result,omitempty"`
	MailFrom string `bson:"mailFrom,omitempty" json:"mailFrom,omitempty"`
	Helo     string `bson:"helo,omitempty" json:"helo,omitempty"`
}

type DKIMResult struct {
	Result   string `bson:"result,omitempty" json:"result,omitempty"`
	Domain   string `bson:"domain,omitempty" json:"domain,omitempty"`
	Selector string `bson:"selector,omitempty" json:"selector,omitempty"`
}

// Original describes the message that failed DMARC, as far as the reporter
// disclosed it (many redact the body and some redact local-parts).
type Original struct {
	From             string              `bson:"from,omitempty" json:"from,omitempty"`
	FromDomain       string              `bson:"fromDomain,omitempty" json:"fromDomain,omitempty"`
	FromOrgDomain    string              `bson:"fromOrgDomain,omitempty" json:"fromOrgDomain,omitempty"`
	To               []string            `bson:"to,omitempty" json:"to,omitempty"`
	ReplyTo          string              `bson:"replyTo,omitempty" json:"replyTo,omitempty"`
	ReturnPath       string              `bson:"returnPath,omitempty" json:"returnPath,omitempty"`
	ReturnPathDomain string              `bson:"returnPathDomain,omitempty" json:"returnPathDomain,omitempty"`
	Subject          string              `bson:"subject,omitempty" json:"subject,omitempty"`
	MessageID        string              `bson:"messageId,omitempty" json:"messageId,omitempty"`
	Date             *time.Time          `bson:"date,omitempty" json:"date,omitempty"`
	XMailer          string              `bson:"xMailer,omitempty" json:"xMailer,omitempty"`
	Received         []string            `bson:"received,omitempty" json:"received,omitempty"`
	DKIMSignatures   []DKIMFields        `bson:"dkimSignatures,omitempty" json:"dkimSignatures,omitempty"`
	Headers          map[string][]string `bson:"headers,omitempty" json:"headers,omitempty"`
}

type MailboxRef struct {
	GraphID           string    `bson:"graphId,omitempty" json:"graphId,omitempty"`
	InternetMessageID string    `bson:"internetMessageId,omitempty" json:"internetMessageId,omitempty"`
	Subject           string    `bson:"subject,omitempty" json:"subject,omitempty"`
	From              string    `bson:"from,omitempty" json:"from,omitempty"`
	ReceivedAt        time.Time `bson:"receivedAt" json:"receivedAt"`
}

// IngestRecord is one row per mailbox message processed (collector health).
type IngestRecord struct {
	InternetMessageID string    `bson:"internetMessageId"`
	GraphID           string    `bson:"graphId"`
	RunID             string    `bson:"runId,omitempty"` // dmarc_collector_runs._id (hex)
	Subject           string    `bson:"subject,omitempty"`
	From              string    `bson:"from,omitempty"`
	ReceivedAt        time.Time `bson:"receivedAt"`
	ProcessedAt       time.Time `bson:"processedAt"`
	Status            string    `bson:"status"` // ok | no_reports | error
	Reports           int       `bson:"reports"`
	Inserted          int       `bson:"inserted"`
	Duplicates        int       `bson:"duplicates"`
	Aggregates        int       `bson:"aggregates"`
	AggInserted       int       `bson:"aggregatesInserted"`
	AggDuplicates     int       `bson:"aggregatesDuplicate"`
	Error             string    `bson:"error,omitempty"`
	Warnings          []string  `bson:"warnings,omitempty"`
	// Structure lists the MIME parts and how each was classified. Stored only
	// for messages in which no report was found, to show why.
	Structure []string `bson:"structure,omitempty"`
}
