// Package config loads sxg-check's JSON configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Duration is a time.Duration written as a string ("1m", "5s").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings such as "1m" or "5s"`)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Config struct {
	Mongo struct {
		URI      string `json:"uri"`
		Database string `json:"database"`
		// EnsureIndexes creates the indexes at start-up. Turn it off and run
		// `datafetch sxg-check -init-db` once if the checker's account may not.
		EnsureIndexes *bool `json:"ensureIndexes"`
	} `json:"mongo"`
	// Instance names this checker in the database. Default: the host name.
	// Checkers in different network zones can share a database; each only
	// removes the firewalls it owns.
	Instance string `json:"instance"`
	// Interval between passes when started with -loop. Default 1m.
	Interval          Duration `json:"interval"`
	HeartbeatInterval Duration `json:"heartbeatInterval"`
	// Concurrency is how many firewalls are checked at once. Default 8.
	Concurrency int `json:"concurrency"`
	Retention   struct {
		LogsDays    int `json:"logsDays"`
		RunsDays    int `json:"runsDays"`
		ResultsDays int `json:"resultsDays"`
		EventsDays  int `json:"eventsDays"`
	} `json:"retention"`
	Logging struct {
		Level      string `json:"level"`      // local log
		MongoLevel string `json:"mongoLevel"` // what is sent to sxg_logs
		Format     string `json:"format"`     // text or json
	} `json:"logging"`

	// Defaults are check settings every firewall starts from. A firewall's
	// own settings are laid over them field by field.
	Defaults  json.RawMessage   `json:"defaults"`
	RawFWs    []json.RawMessage `json:"firewalls"`
	Firewalls []Firewall        `json:"-"`
}

// Firewall is one Sophos firewall and the checks to make on it.
type Firewall struct {
	// Name identifies the firewall in the database and the dashboard.
	Name string `json:"name"`
	// Host is the address the checks connect to: a name or an IP.
	Host string `json:"host"`
	// TenantName, Site and Tags are labels for grouping in the dashboard.
	TenantName string   `json:"tenantName"`
	Site       string   `json:"site"`
	Tags       []string `json:"tags"`
	Checks
}

// Checks are the check settings. A check runs when its block is present
// (here or in defaults) and not switched off with "enabled": false.
type Checks struct {
	// Timeout of one network operation. Default 5s.
	Timeout Duration `json:"timeout"`
	// Retries is how many more times a failed check is tried before it
	// counts. Default 1.
	Retries *int `json:"retries"`

	TCP      *TCP      `json:"tcp"`
	TLS      *TLS      `json:"tls"`
	WebAdmin *WebAdmin `json:"webAdmin"`
	Proxy    *Proxy    `json:"proxy"`
	API      *API      `json:"api"`
	SNMP     *SNMP     `json:"snmp"`
}

// TCP checks that ports accept connections.
type TCP struct {
	Enabled *bool `json:"enabled"`
	Ports   []int `json:"ports"`
}

// TLS reads the certificate a port presents and checks when it expires.
type TLS struct {
	Enabled *bool `json:"enabled"`
	// Ports default to [4444], the web admin console.
	Ports []int `json:"ports"`
	// Days left at which the check warns and turns critical. Default 30, 7.
	WarnDays     int `json:"warnDays"`
	CriticalDays int `json:"criticalDays"`
	// ServerName is sent as SNI. Default: host.
	ServerName string `json:"serverName"`
}

// WebAdmin checks that the web admin console answers over HTTPS.
type WebAdmin struct {
	Enabled *bool `json:"enabled"`
	Port    int   `json:"port"` // default 4444
	// VerifyCertificate checks the certificate chain and name. Off by
	// default: most consoles have a self-signed certificate.
	VerifyCertificate bool `json:"verifyCertificate"`
}

// Proxy sends requests through the firewall's web proxy.
type Proxy struct {
	Enabled *bool `json:"enabled"`
	Port    int   `json:"port"` // default 3128
	// URLs to request through the proxy. An https URL exercises CONNECT.
	URLs []string `json:"urls"`
	// Username and password for a proxy that asks for them (basic).
	Username    string `json:"username"`
	Password    string `json:"password"`
	PasswordEnv string `json:"passwordEnv"`
	// ExpectStatus is the HTTP statuses that count as working. Default:
	// anything from 200 to 399.
	ExpectStatus []int `json:"expectStatus"`
	// Latency at which the check warns or turns critical. Default 2s and
	// off.
	WarnLatency     Duration `json:"warnLatency"`
	CriticalLatency Duration `json:"criticalLatency"`
	// VerifyCertificate checks the certificate of https URLs. Off by
	// default: with HTTPS decryption the firewall re-signs them with its
	// own CA.
	VerifyCertificate bool `json:"verifyCertificate"`
}

// API signs in to the XML API on the web admin port.
type API struct {
	Enabled           *bool  `json:"enabled"`
	Port              int    `json:"port"` // default 4444
	Username          string `json:"username"`
	Password          string `json:"password"`
	PasswordEnv       string `json:"passwordEnv"`
	VerifyCertificate bool   `json:"verifyCertificate"`
}

// Threshold is the value at which a metric warns and turns critical. A
// negative number switches that level off.
type Threshold struct {
	Warn     float64 `json:"warn"`
	Critical float64 `json:"critical"`
}

// SNMP reads the firewall's SFOS-FIREWALL-MIB.
type SNMP struct {
	Enabled *bool `json:"enabled"`
	Port    int   `json:"port"` // default 161
	// Version is "2c" (default) or "3".
	Version      string `json:"version"`
	Community    string `json:"community"`
	CommunityEnv string `json:"communityEnv"`
	// SNMPv3: user, and optionally authentication and privacy.
	Username string `json:"username"`
	// AuthProtocol: SHA (default), SHA224, SHA256, SHA384, SHA512 or MD5.
	AuthProtocol    string `json:"authProtocol"`
	AuthPassword    string `json:"authPassword"`
	AuthPasswordEnv string `json:"authPasswordEnv"`
	// PrivProtocol: AES (default), AES192, AES256 or DES.
	PrivProtocol    string `json:"privProtocol"`
	PrivPassword    string `json:"privPassword"`
	PrivPasswordEnv string `json:"privPasswordEnv"`

	// Percent used. Defaults: cpu 85/95, memory 85/95, swap 50/80,
	// disk 80/90.
	CPU    Threshold `json:"cpu"`
	Memory Threshold `json:"memory"`
	Swap   Threshold `json:"swap"`
	Disk   Threshold `json:"disk"`

	// RequiredServices must be running: "http", "dns", "ips"... A dead or
	// frozen service is critical whether listed or not.
	RequiredServices []string `json:"requiredServices"`
	// IgnoreServices are left out of the check altogether.
	IgnoreServices []string `json:"ignoreServices"`
	// LicenseWarnDays warns this many days before a subscription expires.
	// Default 30.
	LicenseWarnDays int `json:"licenseWarnDays"`
	// IgnoreLicenses are left out: "mail", "webserver"...
	IgnoreLicenses []string `json:"ignoreLicenses"`
	// ExpectHA is the HA state this firewall should be in: primary,
	// auxiliary or standalone. Another state warns (a failover happened).
	ExpectHA string `json:"expectHa"`
}

func on(b *bool) bool { return b == nil || *b }

func (c *Config) EnsureIndexes() bool { return on(c.Mongo.EnsureIndexes) }

func (k *Checks) TCPOn() bool      { return k.TCP != nil && on(k.TCP.Enabled) }
func (k *Checks) TLSOn() bool      { return k.TLS != nil && on(k.TLS.Enabled) }
func (k *Checks) WebAdminOn() bool { return k.WebAdmin != nil && on(k.WebAdmin.Enabled) }
func (k *Checks) ProxyOn() bool    { return k.Proxy != nil && on(k.Proxy.Enabled) }
func (k *Checks) APIOn() bool      { return k.API != nil && on(k.API.Enabled) }
func (k *Checks) SNMPOn() bool     { return k.SNMP != nil && on(k.SNMP.Enabled) }

// Attempts is how many times a check is tried.
func (k *Checks) Attempts() int { return 1 + *k.Retries }

// ServiceNames are the services of the SFOS MIB, in its order.
var ServiceNames = []string{"pop3", "imap4", "smtp", "ftp", "http", "av", "as", "dns", "ha", "ips", "apache", "ntp", "tomcat", "sslvpn", "ipsec", "database", "network", "garner", "drouting", "sshd", "dgd"}

// LicenseNames are the subscriptions of the SFOS MIB, in its order.
var LicenseNames = []string{"base", "network", "web", "mail", "webserver", "sandstorm", "enhancedsupport", "enhancedplussupport", "centralorchestration"}

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	hostRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,253}$`)
)

// Load reads and validates the file. Environment variables override the
// MongoDB settings (SXGCHECK_MONGO_URI, SXGCHECK_MONGO_DATABASE) and can
// supply the firewalls (SXGCHECK_FIREWALLS, a JSON array, or
// SXGCHECK_FIREWALLS_FILE).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, os.Getenv, os.ReadFile)
}

func strict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func Parse(b []byte, getenv func(string) string, readFile func(string) ([]byte, error)) (*Config, error) {
	var c Config
	if err := strict(b, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if v := getenv("SXGCHECK_MONGO_URI"); v != "" {
		c.Mongo.URI = v
	}
	if v := getenv("SXGCHECK_MONGO_DATABASE"); v != "" {
		c.Mongo.Database = v
	}
	if f := getenv("SXGCHECK_FIREWALLS_FILE"); f != "" {
		raw, err := readFile(f)
		if err != nil {
			return nil, fmt.Errorf("config: SXGCHECK_FIREWALLS_FILE: %w", err)
		}
		c.RawFWs = nil
		if err := json.Unmarshal(raw, &c.RawFWs); err != nil {
			return nil, fmt.Errorf("config: %s: expected a JSON array of firewalls: %w", f, err)
		}
	}
	if v := getenv("SXGCHECK_FIREWALLS"); v != "" {
		c.RawFWs = nil
		if err := json.Unmarshal([]byte(v), &c.RawFWs); err != nil {
			return nil, fmt.Errorf("config: SXGCHECK_FIREWALLS: expected a JSON array of firewalls: %w", err)
		}
	}
	if c.Mongo.Database == "" {
		c.Mongo.Database = "sxgcheck"
	}
	c.Instance = strings.TrimSpace(c.Instance)
	if c.Interval == 0 {
		c.Interval = Duration(time.Minute)
	}
	if c.Interval.D() < 10*time.Second {
		return nil, errors.New("config: interval must be at least 10s")
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = Duration(30 * time.Second)
	}
	// The dashboard treats a run as stalled after five minutes of silence.
	if hb := c.HeartbeatInterval.D(); hb < 5*time.Second || hb > time.Minute {
		return nil, errors.New("config: heartbeatInterval must be between 5s and 1m")
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	for _, r := range []struct {
		v   *int
		def int
	}{{&c.Retention.LogsDays, 30}, {&c.Retention.RunsDays, 14}, {&c.Retention.ResultsDays, 30}, {&c.Retention.EventsDays, 180}} {
		if *r.v == 0 {
			*r.v = r.def
		}
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.MongoLevel == "" {
		c.Logging.MongoLevel = "info"
	}

	if len(c.Defaults) > 0 {
		var probe Checks
		if err := strict(c.Defaults, &probe); err != nil {
			return nil, fmt.Errorf("config: defaults: %w", err)
		}
	}
	if len(c.RawFWs) == 0 {
		return nil, errors.New("config: no firewalls configured (firewalls, SXGCHECK_FIREWALLS or SXGCHECK_FIREWALLS_FILE)")
	}
	seen := map[string]bool{}
	for i, raw := range c.RawFWs {
		var fw Firewall
		// Defaults first, into a fresh value each time, then the firewall's
		// own settings over them.
		if len(c.Defaults) > 0 {
			_ = strict(c.Defaults, &fw.Checks)
		}
		where := fmt.Sprintf("config: firewalls[%d]", i)
		if err := strict(raw, &fw); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		fw.Name, fw.Host = strings.TrimSpace(fw.Name), strings.TrimSpace(fw.Host)
		if !nameRe.MatchString(fw.Name) {
			return nil, fmt.Errorf("%s: name is required: letters, digits, dot, dash and underscore, at most 64", where)
		}
		where += " (" + fw.Name + ")"
		if seen[strings.ToLower(fw.Name)] {
			return nil, fmt.Errorf("%s: the name is used twice", where)
		}
		seen[strings.ToLower(fw.Name)] = true
		if !hostRe.MatchString(fw.Host) {
			return nil, fmt.Errorf("%s: host must be a host name or an IP address, without scheme or port", where)
		}
		if err := fw.Checks.finish(getenv); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		c.Firewalls = append(c.Firewalls, fw)
	}
	return &c, nil
}

func port(name string, p *int, def int) error {
	if *p == 0 {
		*p = def
	}
	if *p < 1 || *p > 65535 {
		return fmt.Errorf("%s: %d is not a port", name, *p)
	}
	return nil
}

func ports(name string, list []int) error {
	for i := range list {
		if err := port(name, &list[i], 0); err != nil {
			return err
		}
	}
	return nil
}

func secret(getenv func(string) string, value *string, env string) {
	if env != "" {
		if v := getenv(env); v != "" {
			*value = v
		}
	}
}

func threshold(t *Threshold, warn, critical float64) {
	if t.Warn == 0 && t.Critical == 0 {
		t.Warn, t.Critical = warn, critical
	}
}

func known(name string, list, allowed []string) error {
	for i, s := range list {
		list[i] = strings.ToLower(strings.TrimSpace(s))
		ok := false
		for _, a := range allowed {
			ok = ok || a == list[i]
		}
		if !ok {
			return fmt.Errorf("%s: %q is not one of %s", name, s, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// finish applies defaults and validates the checks of one firewall.
func (k *Checks) finish(getenv func(string) string) error {
	if k.Timeout == 0 {
		k.Timeout = Duration(5 * time.Second)
	}
	if t := k.Timeout.D(); t < 500*time.Millisecond || t > time.Minute {
		return errors.New("timeout must be between 500ms and 1m")
	}
	if k.Retries == nil {
		one := 1
		k.Retries = &one
	}
	if *k.Retries < 0 || *k.Retries > 5 {
		return errors.New("retries must be between 0 and 5")
	}
	if !(k.TCPOn() || k.TLSOn() || k.WebAdminOn() || k.ProxyOn() || k.APIOn() || k.SNMPOn()) {
		return errors.New("no checks are configured: add tcp, tls, webAdmin, proxy, api or snmp here or in defaults")
	}
	if k.TCPOn() {
		if len(k.TCP.Ports) == 0 {
			return errors.New("tcp.ports is empty")
		}
		if err := ports("tcp.ports", k.TCP.Ports); err != nil {
			return err
		}
	}
	if k.TLSOn() {
		t := k.TLS
		if len(t.Ports) == 0 {
			t.Ports = []int{4444}
		}
		if err := ports("tls.ports", t.Ports); err != nil {
			return err
		}
		if t.WarnDays == 0 && t.CriticalDays == 0 {
			t.WarnDays, t.CriticalDays = 30, 7
		}
		if t.CriticalDays > t.WarnDays {
			return errors.New("tls.criticalDays is more than tls.warnDays")
		}
	}
	if k.WebAdminOn() {
		if err := port("webAdmin.port", &k.WebAdmin.Port, 4444); err != nil {
			return err
		}
	}
	if k.ProxyOn() {
		p := k.Proxy
		if err := port("proxy.port", &p.Port, 3128); err != nil {
			return err
		}
		if len(p.URLs) == 0 {
			p.URLs = []string{"http://www.msftconnecttest.com/connecttest.txt"}
		}
		for _, raw := range p.URLs {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
				return fmt.Errorf("proxy.urls: %q is not an http or https URL", raw)
			}
		}
		secret(getenv, &p.Password, p.PasswordEnv)
		if p.Username != "" && p.Password == "" {
			return errors.New("proxy.username is set without a password (password or passwordEnv)")
		}
		if p.WarnLatency == 0 {
			p.WarnLatency = Duration(2 * time.Second)
		}
		for _, s := range p.ExpectStatus {
			if s < 100 || s > 599 {
				return fmt.Errorf("proxy.expectStatus: %d is not an HTTP status", s)
			}
		}
	}
	if k.APIOn() {
		a := k.API
		if err := port("api.port", &a.Port, 4444); err != nil {
			return err
		}
		secret(getenv, &a.Password, a.PasswordEnv)
		if a.Username == "" || a.Password == "" {
			return errors.New("api needs username and a password (password or passwordEnv)")
		}
	}
	if k.SNMPOn() {
		s := k.SNMP
		if err := port("snmp.port", &s.Port, 161); err != nil {
			return err
		}
		secret(getenv, &s.Community, s.CommunityEnv)
		secret(getenv, &s.AuthPassword, s.AuthPasswordEnv)
		secret(getenv, &s.PrivPassword, s.PrivPasswordEnv)
		s.Version = strings.ToLower(strings.TrimPrefix(strings.ToLower(s.Version), "v"))
		switch s.Version {
		case "", "2", "2c":
			s.Version = "2c"
			if s.Community == "" {
				return errors.New("snmp needs a community (community or communityEnv)")
			}
		case "3":
			if s.Username == "" {
				return errors.New("snmp version 3 needs a username")
			}
			s.AuthProtocol, s.PrivProtocol = strings.ToUpper(s.AuthProtocol), strings.ToUpper(s.PrivProtocol)
			if s.AuthPassword != "" && s.AuthProtocol == "" {
				s.AuthProtocol = "SHA"
			}
			if s.PrivPassword != "" && s.PrivProtocol == "" {
				s.PrivProtocol = "AES"
			}
			if s.PrivPassword != "" && s.AuthPassword == "" {
				return errors.New("snmp privacy needs authentication too (authPassword)")
			}
			if s.AuthPassword != "" && !in(s.AuthProtocol, "MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512") {
				return fmt.Errorf("snmp.authProtocol: %q is not MD5, SHA, SHA224, SHA256, SHA384 or SHA512", s.AuthProtocol)
			}
			if s.PrivPassword != "" && !in(s.PrivProtocol, "DES", "AES", "AES192", "AES256") {
				return fmt.Errorf("snmp.privProtocol: %q is not DES, AES, AES192 or AES256", s.PrivProtocol)
			}
		default:
			return fmt.Errorf("snmp.version: %q is not 2c or 3", s.Version)
		}
		threshold(&s.CPU, 85, 95)
		threshold(&s.Memory, 85, 95)
		threshold(&s.Swap, 50, 80)
		threshold(&s.Disk, 80, 90)
		if s.LicenseWarnDays == 0 {
			s.LicenseWarnDays = 30
		}
		if err := known("snmp.requiredServices", s.RequiredServices, ServiceNames); err != nil {
			return err
		}
		if err := known("snmp.ignoreServices", s.IgnoreServices, ServiceNames); err != nil {
			return err
		}
		if err := known("snmp.ignoreLicenses", s.IgnoreLicenses, LicenseNames); err != nil {
			return err
		}
		s.ExpectHA = strings.ToLower(s.ExpectHA)
		if !in(s.ExpectHA, "", "primary", "auxiliary", "standalone") {
			return fmt.Errorf("snmp.expectHa: %q is not primary, auxiliary or standalone", s.ExpectHA)
		}
	}
	return nil
}

func in(s string, list ...string) bool {
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
}
