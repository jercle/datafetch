package dmarcreporting

import (
	"strings"
	"testing"

	"github.com/jercle/datafetch/dmarcreporting/internal/config"
	"time"

	"github.com/jercle/datafetch/internal/settings"
)

// merged lays settings over a configuration file and expects every one of
// them to be taken.
func merged(t *testing.T, file []byte, flat map[string]any, applied int) []byte {
	t.Helper()
	keyed := map[string]any{}
	for k, v := range flat {
		keyed[settings.Key(Spec.Tool)+"."+k] = v
	}
	r, err := settings.Merge(file, settings.Nest(keyed), Spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) != 0 || r.Applied != applied {
		t.Fatalf("applied %d of %d settings; warnings:\n%s", r.Applied, applied, strings.Join(r.Warnings, "\n"))
	}
	return r.Config
}

func none(string) string { return "" }

// The environment, written as JSON and read back, is the same configuration.
func TestTheEnvironmentAsJSON(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("DMARC_MAILBOX", "dmarc@example.com")
	t.Setenv("DMARC_POLL_INTERVAL", "90s")
	t.Setenv("REVERSE_DNS", "false")
	t.Setenv("GRAPH_ENDPOINT", "https://graph.microsoft.us/")
	env := config.Load()
	b, err := env.JSON()
	if err != nil {
		t.Fatal(err)
	}
	back, err := config.Parse(merged(t, b, nil, 0))
	if err != nil {
		t.Fatal(err)
	}
	if *back != *env || back.PollInterval != 90*time.Second || back.ReverseDNS || back.GraphEndpoint != "https://graph.microsoft.us" || back.MongoRuns != "dmarc_collector_runs" {
		t.Errorf("\n%+v\n%+v", env, back)
	}
}

func TestSettingsOverTheEnvironment(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "client")
	t.Setenv("DMARC_MAILBOX", "env@example.com")
	t.Setenv("DMARC_BATCH_SIZE", "10")
	env := config.Load()
	if env.ValidateService() == nil {
		t.Fatal("no secret yet: not valid")
	}
	b, _ := env.JSON()
	c, err := config.Parse(merged(t, b, map[string]any{
		"clientSecret":                "from-app-config",
		"mailbox":                     "appconfig@example.com",
		"postProcess":                 "MarkRead",
		"pollInterval":                "10m",
		"batchSize":                   "50",
		"mongo.uri":                   "mongodb://db",
		"mongo.runsCollection":        "runs",
		"reverseDns":                  "false",
		"dnsTimeout":                  "1s",
		"storeRawFields":              false,
		"monitoring.enabled":          "false",
		"monitoring.logRetentionDays": 7,
		"authorityHost":               "https://login.microsoftonline.us/",
	}, 13))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateService(); err != nil {
		t.Fatal(err)
	}
	if c.TenantID != "tenant" || c.ClientSecret != "from-app-config" || c.Mailbox != "appconfig@example.com" || c.PostProcess != "markread" ||
		c.PollInterval != 10*time.Minute || c.BatchSize != 50 || c.MongoURI != "mongodb://db" || c.MongoRuns != "runs" || c.MongoLogs != "dmarc_collector_logs" ||
		c.ReverseDNS || c.DNSTimeout != time.Second || c.StoreRawFields || c.MonitoringEnabled || c.LogRetentionDays != 7 || c.RunRetentionDays != 180 ||
		c.AuthorityHost != "https://login.microsoftonline.us" {
		t.Errorf("%+v", c)
	}
	// Only what Reconfigure takes differs in the part read at the start.
	next := *c
	next.PollInterval, next.BatchSize, next.SourceFolder, next.RedactSubject = time.Hour, 5, "Inbox/Other", true
	if fixed(&next) != fixed(c) {
		t.Error("the poll settings are not read at the start only")
	}
	next.Mailbox = "other@example.com"
	if fixed(&next) == fixed(c) {
		t.Error("the mailbox is read at the start only")
	}
}
