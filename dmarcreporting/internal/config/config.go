// Package config loads collector settings from environment variables, and
// reads them as JSON: the shape the settings under
// datafetching.dmarcReporting in Azure App Configuration are laid over.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Entra ID app registration (client credentials). Either ClientSecret or
	// FederatedTokenFile (AKS workload identity) must be set.
	TenantID           string
	ClientID           string
	ClientSecret       string
	FederatedTokenFile string
	AuthorityHost      string
	GraphEndpoint      string

	Mailbox         string
	SourceFolder    string // e.g. "Inbox" or "Inbox/DMARC"
	ProcessedFolder string // created if missing (move mode)
	FailedFolder    string // created if missing (move mode)
	PostProcess     string // "move" | "markread"
	PollInterval    time.Duration
	BatchSize       int

	MongoURI        string
	MongoDB         string
	MongoCollection string
	MongoIngestColl string
	MongoAggReports string
	MongoAggRecords string

	GeoIPCityDB string // MaxMind GeoLite2-City.mmdb / GeoIP2-City.mmdb
	GeoIPASNDB  string // MaxMind GeoLite2-ASN.mmdb
	IPInfoToken string // optional fallback / supplement (ipinfo Lite API)
	ReverseDNS  bool
	DNSTimeout  time.Duration

	SaveUnparsedDir      string // write messages with no report here as .eml (debugging)
	RedactSubject        bool
	StoreOriginalHeaders bool
	StoreRawFields       bool

	// Monitoring: run records, logs and a heartbeat written to MongoDB.
	MonitoringEnabled bool
	MonitoringLevel   string // minimum level stored in MongoDB
	LogRetentionDays  int
	RunRetentionDays  int
	MongoRuns         string
	MongoLogs         string
	MongoInstances    string
	InstanceName      string // defaults to the hostname

	HealthAddr string
	LogLevel   string
}

func Load() *Config {
	return &Config{
		TenantID:           env("AZURE_TENANT_ID", ""),
		ClientID:           env("AZURE_CLIENT_ID", ""),
		ClientSecret:       env("AZURE_CLIENT_SECRET", ""),
		FederatedTokenFile: env("AZURE_FEDERATED_TOKEN_FILE", ""),
		AuthorityHost:      strings.TrimRight(env("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com"), "/"),
		GraphEndpoint:      strings.TrimRight(env("GRAPH_ENDPOINT", "https://graph.microsoft.com"), "/"),

		Mailbox:         env("DMARC_MAILBOX", ""),
		SourceFolder:    env("DMARC_SOURCE_FOLDER", "Inbox"),
		ProcessedFolder: env("DMARC_PROCESSED_FOLDER", "Inbox/DMARC-Processed"),
		FailedFolder:    env("DMARC_FAILED_FOLDER", "Inbox/DMARC-Failed"),
		PostProcess:     strings.ToLower(env("DMARC_POST_PROCESS", "move")),
		PollInterval:    envDur("DMARC_POLL_INTERVAL", 5*time.Minute),
		BatchSize:       envInt("DMARC_BATCH_SIZE", 25),

		MongoURI:        env("MONGODB_URI", "mongodb://localhost:27017"),
		MongoDB:         env("MONGODB_DATABASE", "dmarc"),
		MongoCollection: env("MONGODB_COLLECTION", "dmarc_failures"),
		MongoIngestColl: env("MONGODB_INGEST_COLLECTION", "dmarc_ingest"),
		MongoAggReports: env("MONGODB_AGGREGATE_REPORTS_COLLECTION", "dmarc_aggregate_reports"),
		MongoAggRecords: env("MONGODB_AGGREGATE_RECORDS_COLLECTION", "dmarc_aggregate_records"),

		GeoIPCityDB: env("GEOIP_CITY_DB", ""),
		GeoIPASNDB:  env("GEOIP_ASN_DB", ""),
		IPInfoToken: env("IPINFO_TOKEN", ""),
		ReverseDNS:  envBool("REVERSE_DNS", true),
		DNSTimeout:  envDur("DNS_TIMEOUT", 3*time.Second),

		SaveUnparsedDir:      env("DMARC_SAVE_UNPARSED_DIR", ""),
		RedactSubject:        envBool("REDACT_SUBJECT", false),
		StoreOriginalHeaders: envBool("STORE_ORIGINAL_HEADERS", false),
		StoreRawFields:       envBool("STORE_RAW_FIELDS", true),

		MonitoringEnabled: envBool("MONITORING_ENABLED", true),
		MonitoringLevel:   env("MONITORING_LOG_LEVEL", "info"),
		LogRetentionDays:  envInt("MONITORING_LOG_RETENTION_DAYS", 30),
		RunRetentionDays:  envInt("MONITORING_RUN_RETENTION_DAYS", 180),
		MongoRuns:         env("MONGODB_RUNS_COLLECTION", "dmarc_collector_runs"),
		MongoLogs:         env("MONGODB_LOGS_COLLECTION", "dmarc_collector_logs"),
		MongoInstances:    env("MONGODB_INSTANCES_COLLECTION", "dmarc_collector_instances"),
		InstanceName:      env("INSTANCE_NAME", ""),

		HealthAddr: env("HEALTH_ADDR", ":8080"),
		LogLevel:   env("LOG_LEVEL", "info"),
	}
}

// Duration is a time.Duration written as a string ("5m", "3s").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings such as "5m" or "30s"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// File is the configuration as JSON. Its paths are the settings under
// datafetching.dmarcReporting; each is named with the environment variable
// that sets the same thing.
type File struct {
	TenantID           string `json:"tenantId"`           // AZURE_TENANT_ID
	ClientID           string `json:"clientId"`           // AZURE_CLIENT_ID
	ClientSecret       string `json:"clientSecret"`       // AZURE_CLIENT_SECRET
	FederatedTokenFile string `json:"federatedTokenFile"` // AZURE_FEDERATED_TOKEN_FILE
	AuthorityHost      string `json:"authorityHost"`      // AZURE_AUTHORITY_HOST
	GraphEndpoint      string `json:"graphEndpoint"`      // GRAPH_ENDPOINT

	Mailbox         string   `json:"mailbox"`         // DMARC_MAILBOX
	SourceFolder    string   `json:"sourceFolder"`    // DMARC_SOURCE_FOLDER
	ProcessedFolder string   `json:"processedFolder"` // DMARC_PROCESSED_FOLDER
	FailedFolder    string   `json:"failedFolder"`    // DMARC_FAILED_FOLDER
	PostProcess     string   `json:"postProcess"`     // DMARC_POST_PROCESS
	PollInterval    Duration `json:"pollInterval"`    // DMARC_POLL_INTERVAL
	BatchSize       int      `json:"batchSize"`       // DMARC_BATCH_SIZE

	Mongo struct {
		URI                        string `json:"uri"`                        // MONGODB_URI
		Database                   string `json:"database"`                   // MONGODB_DATABASE
		Collection                 string `json:"collection"`                 // MONGODB_COLLECTION
		IngestCollection           string `json:"ingestCollection"`           // MONGODB_INGEST_COLLECTION
		AggregateReportsCollection string `json:"aggregateReportsCollection"` // MONGODB_AGGREGATE_REPORTS_COLLECTION
		AggregateRecordsCollection string `json:"aggregateRecordsCollection"` // MONGODB_AGGREGATE_RECORDS_COLLECTION
		RunsCollection             string `json:"runsCollection"`             // MONGODB_RUNS_COLLECTION
		LogsCollection             string `json:"logsCollection"`             // MONGODB_LOGS_COLLECTION
		InstancesCollection        string `json:"instancesCollection"`        // MONGODB_INSTANCES_COLLECTION
	} `json:"mongo"`

	GeoIPCityDB string   `json:"geoipCityDb"` // GEOIP_CITY_DB
	GeoIPASNDB  string   `json:"geoipAsnDb"`  // GEOIP_ASN_DB
	IPInfoToken string   `json:"ipinfoToken"` // IPINFO_TOKEN
	ReverseDNS  bool     `json:"reverseDns"`  // REVERSE_DNS
	DNSTimeout  Duration `json:"dnsTimeout"`  // DNS_TIMEOUT

	SaveUnparsedDir      string `json:"saveUnparsedDir"`      // DMARC_SAVE_UNPARSED_DIR
	RedactSubject        bool   `json:"redactSubject"`        // REDACT_SUBJECT
	StoreOriginalHeaders bool   `json:"storeOriginalHeaders"` // STORE_ORIGINAL_HEADERS
	StoreRawFields       bool   `json:"storeRawFields"`       // STORE_RAW_FIELDS

	Monitoring struct {
		Enabled          bool   `json:"enabled"`          // MONITORING_ENABLED
		LogLevel         string `json:"logLevel"`         // MONITORING_LOG_LEVEL
		LogRetentionDays int    `json:"logRetentionDays"` // MONITORING_LOG_RETENTION_DAYS
		RunRetentionDays int    `json:"runRetentionDays"` // MONITORING_RUN_RETENTION_DAYS
	} `json:"monitoring"`

	InstanceName string `json:"instanceName"` // INSTANCE_NAME
	HealthAddr   string `json:"healthAddr"`   // HEALTH_ADDR
	LogLevel     string `json:"logLevel"`     // LOG_LEVEL
}

// JSON writes the configuration in the shape of File.
func (c *Config) JSON() ([]byte, error) {
	var f File
	f.TenantID, f.ClientID, f.ClientSecret, f.FederatedTokenFile = c.TenantID, c.ClientID, c.ClientSecret, c.FederatedTokenFile
	f.AuthorityHost, f.GraphEndpoint = c.AuthorityHost, c.GraphEndpoint
	f.Mailbox, f.SourceFolder, f.ProcessedFolder, f.FailedFolder = c.Mailbox, c.SourceFolder, c.ProcessedFolder, c.FailedFolder
	f.PostProcess, f.PollInterval, f.BatchSize = c.PostProcess, Duration(c.PollInterval), c.BatchSize
	f.Mongo.URI, f.Mongo.Database, f.Mongo.Collection, f.Mongo.IngestCollection = c.MongoURI, c.MongoDB, c.MongoCollection, c.MongoIngestColl
	f.Mongo.AggregateReportsCollection, f.Mongo.AggregateRecordsCollection = c.MongoAggReports, c.MongoAggRecords
	f.Mongo.RunsCollection, f.Mongo.LogsCollection, f.Mongo.InstancesCollection = c.MongoRuns, c.MongoLogs, c.MongoInstances
	f.GeoIPCityDB, f.GeoIPASNDB, f.IPInfoToken, f.ReverseDNS, f.DNSTimeout = c.GeoIPCityDB, c.GeoIPASNDB, c.IPInfoToken, c.ReverseDNS, Duration(c.DNSTimeout)
	f.SaveUnparsedDir, f.RedactSubject, f.StoreOriginalHeaders, f.StoreRawFields = c.SaveUnparsedDir, c.RedactSubject, c.StoreOriginalHeaders, c.StoreRawFields
	f.Monitoring.Enabled, f.Monitoring.LogLevel = c.MonitoringEnabled, c.MonitoringLevel
	f.Monitoring.LogRetentionDays, f.Monitoring.RunRetentionDays = c.LogRetentionDays, c.RunRetentionDays
	f.InstanceName, f.HealthAddr, f.LogLevel = c.InstanceName, c.HealthAddr, c.LogLevel
	return json.Marshal(f)
}

// Parse reads configuration JSON in the shape of File. Every value is
// expected to be there, as in what JSON writes: nothing is defaulted.
func Parse(b []byte) (*Config, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &Config{
		TenantID: f.TenantID, ClientID: f.ClientID, ClientSecret: f.ClientSecret, FederatedTokenFile: f.FederatedTokenFile,
		AuthorityHost: strings.TrimRight(f.AuthorityHost, "/"), GraphEndpoint: strings.TrimRight(f.GraphEndpoint, "/"),
		Mailbox: f.Mailbox, SourceFolder: f.SourceFolder, ProcessedFolder: f.ProcessedFolder, FailedFolder: f.FailedFolder,
		PostProcess: strings.ToLower(f.PostProcess), PollInterval: time.Duration(f.PollInterval), BatchSize: f.BatchSize,
		MongoURI: f.Mongo.URI, MongoDB: f.Mongo.Database, MongoCollection: f.Mongo.Collection, MongoIngestColl: f.Mongo.IngestCollection,
		MongoAggReports: f.Mongo.AggregateReportsCollection, MongoAggRecords: f.Mongo.AggregateRecordsCollection,
		GeoIPCityDB: f.GeoIPCityDB, GeoIPASNDB: f.GeoIPASNDB, IPInfoToken: f.IPInfoToken, ReverseDNS: f.ReverseDNS, DNSTimeout: time.Duration(f.DNSTimeout),
		SaveUnparsedDir: f.SaveUnparsedDir, RedactSubject: f.RedactSubject, StoreOriginalHeaders: f.StoreOriginalHeaders, StoreRawFields: f.StoreRawFields,
		MonitoringEnabled: f.Monitoring.Enabled, MonitoringLevel: f.Monitoring.LogLevel,
		LogRetentionDays: f.Monitoring.LogRetentionDays, RunRetentionDays: f.Monitoring.RunRetentionDays,
		MongoRuns: f.Mongo.RunsCollection, MongoLogs: f.Mongo.LogsCollection, MongoInstances: f.Mongo.InstancesCollection,
		InstanceName: f.InstanceName, HealthAddr: f.HealthAddr, LogLevel: f.LogLevel,
	}, nil
}

// ValidateService checks the settings needed to poll a mailbox and write to Mongo.
func (c *Config) ValidateService() error {
	var errs []error
	// Each is named as the setting and as the environment variable.
	for _, r := range []struct{ name, value string }{
		{"tenantId (AZURE_TENANT_ID)", c.TenantID}, {"clientId (AZURE_CLIENT_ID)", c.ClientID},
		{"mailbox (DMARC_MAILBOX)", c.Mailbox}, {"mongo.uri (MONGODB_URI)", c.MongoURI},
	} {
		if r.value == "" {
			errs = append(errs, fmt.Errorf("%s is required", r.name))
		}
	}
	if c.ClientSecret == "" && c.FederatedTokenFile == "" {
		errs = append(errs, errors.New("set clientSecret (AZURE_CLIENT_SECRET) or federatedTokenFile (AZURE_FEDERATED_TOKEN_FILE)"))
	}
	if c.PostProcess != "move" && c.PostProcess != "markread" {
		errs = append(errs, fmt.Errorf("postProcess (DMARC_POST_PROCESS) must be move or markread, got %q", c.PostProcess))
	}
	if c.LogRetentionDays < 1 || c.RunRetentionDays < 1 {
		errs = append(errs, errors.New("monitoring.logRetentionDays and monitoring.runRetentionDays (MONITORING_*_RETENTION_DAYS) must be at least 1"))
	}
	if c.BatchSize < 1 || c.BatchSize > 100 {
		errs = append(errs, errors.New("batchSize (DMARC_BATCH_SIZE) must be 1-100"))
	}
	if c.PollInterval < time.Second {
		errs = append(errs, errors.New("pollInterval (DMARC_POLL_INTERVAL) must be at least 1s"))
	}
	return errors.Join(errs...)
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envBool(k string, def bool) bool {
	if b, err := strconv.ParseBool(env(k, "")); err == nil {
		return b
	}
	return def
}

func envInt(k string, def int) int {
	if i, err := strconv.Atoi(env(k, "")); err == nil {
		return i
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(env(k, "")); err == nil {
		return d
	}
	return def
}
