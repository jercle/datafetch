package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jercle/datafetch/sxgcheck/internal/config"
	"github.com/jercle/datafetch/sxgcheck/internal/model"
)

// firewall builds a validated config.Firewall on 127.0.0.1 from JSON check
// settings.
func firewall(t *testing.T, checks string) config.Firewall {
	t.Helper()
	c, err := config.Parse([]byte(`{"firewalls":[{"name":"fw","host":"127.0.0.1","timeout":"2s","retries":0,`+checks+`}]}`),
		func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Firewalls[0]
}

func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	u, _ := url.Parse(rawURL)
	p, _ := strconv.Atoi(u.Port())
	return p
}

func byID(t *testing.T, r Result, id string) model.Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", id, r.Checks)
	return model.Check{}
}

func TestTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	open := ln.Addr().(*net.TCPAddr).Port
	// A port that was open and is now closed refuses connections.
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()
	defer ln.Close()

	p := &Prober{}
	r := p.Probe(context.Background(), firewall(t, fmt.Sprintf(`"tcp":{"ports":[%d,%d]}`, open, closed)))
	if len(r.Checks) != 2 {
		t.Fatalf("%+v", r.Checks)
	}
	if c := r.Checks[0]; c.Status != model.HealthOK || c.LatencyMs == nil || c.ID != fmt.Sprintf("tcp/%d", open) {
		t.Fatalf("%+v", c)
	}
	if c := r.Checks[1]; c.Status != model.HealthCritical || !strings.Contains(c.Message, "refused") {
		t.Fatalf("%+v", c)
	}
}

func certServer(t *testing.T, notBefore, notAfter time.Time) int {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Appliance_Certificate"}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); time.Sleep(50 * time.Millisecond); c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestTLSExpiry(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	cases := []struct {
		before, after time.Duration
		want, text    string
	}{
		{-day, 400 * day, model.HealthOK, "valid for"},
		{-day, 20*day + time.Hour, model.HealthWarning, "expires in 20 days"},
		{-day, 3*day + time.Hour, model.HealthCritical, "expires in 3 days"},
		{-10 * day, -day, model.HealthCritical, "expired on"},
		{day, 30 * day, model.HealthCritical, "not valid until"},
	}
	for _, tc := range cases {
		port := certServer(t, now.Add(tc.before), now.Add(tc.after))
		p := &Prober{}
		r := p.Probe(context.Background(), firewall(t, fmt.Sprintf(`"tls":{"ports":[%d]}`, port)))
		c := r.Checks[0]
		if c.Status != tc.want || !strings.Contains(c.Message, tc.text) || !strings.Contains(c.Message, "Appliance_Certificate") || c.Value == nil {
			t.Errorf("%v: %+v", tc, c)
		}
	}
	// Not TLS at all.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	r := (&Prober{}).Probe(context.Background(), firewall(t, fmt.Sprintf(`"tls":{"ports":[%d]}`, ln.Addr().(*net.TCPAddr).Port)))
	if r.Checks[0].Status != model.HealthCritical || !strings.Contains(r.Checks[0].Message, "no TLS handshake") {
		t.Fatalf("%+v", r.Checks[0])
	}
}

func TestWebAdminAndAPI(t *testing.T) {
	var answer atomic.Value
	answer.Store(`<?xml version="1.0" encoding="UTF-8"?><Response APIVersion="2000.1" IPS_CAT_VER="1"><Login><status>Authentication Successful</status></Login></Response>`)
	var gotXML atomic.Value
	status := atomic.Int32{}
	status.Store(200)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/webconsole/APIController" {
			if r.Method != http.MethodPost {
				http.Error(w, "method", 405)
				return
			}
			_ = r.ParseMultipartForm(1 << 20)
			gotXML.Store(r.FormValue("reqxml"))
			_, _ = io.WriteString(w, answer.Load().(string))
			return
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)
	fw := firewall(t, fmt.Sprintf(`"webAdmin":{"port":%d},"api":{"port":%d,"username":"mon","password":"p<&>w"}`, port, port))
	p := &Prober{}

	r := p.Probe(context.Background(), fw)
	if c := byID(t, r, "webadmin"); c.Status != model.HealthOK || !strings.Contains(c.Message, "HTTP 200") {
		t.Fatalf("%+v", c)
	}
	if c := byID(t, r, "api"); c.Status != model.HealthOK || !strings.Contains(c.Message, "2000.1") || strings.Contains(c.Message, "p<") {
		t.Fatalf("%+v", c)
	}
	if r.Device == nil || r.Device.APIVersion != "2000.1" {
		t.Fatalf("device %+v", r.Device)
	}
	// The password is XML-escaped and the request only signs in.
	if x := gotXML.Load().(string); x != "<Request><Login><Username>mon</Username><Password>p&lt;&amp;&gt;w</Password></Login></Request>" {
		t.Fatalf("request %s", x)
	}

	answer.Store(`<Response APIVersion="2000.1"><Login><status>Authentication Failure</status></Login></Response>`)
	status.Store(503)
	r = p.Probe(context.Background(), fw)
	if c := byID(t, r, "api"); c.Status != model.HealthCritical || !strings.Contains(c.Message, "Authentication Failure") {
		t.Fatalf("%+v", c)
	}
	if c := byID(t, r, "webadmin"); c.Status != model.HealthCritical || !strings.Contains(c.Message, "503") {
		t.Fatalf("%+v", c)
	}

	answer.Store(`<Response APIVersion="2000.1"><Status code="534">API operations are not allowed from the requester IP address.</Status></Response>`)
	if c := byID(t, p.Probe(context.Background(), fw), "api"); c.Status != model.HealthCritical || !strings.Contains(c.Message, "not allowed") || !strings.Contains(c.Message, "534") {
		t.Fatalf("%+v", c)
	}
	answer.Store(`<html>login page</html>`)
	if c := byID(t, p.Probe(context.Background(), fw), "api"); c.Status != model.HealthCritical {
		t.Fatalf("%+v", c)
	}

	// With verification on, the test server's certificate is not trusted.
	strictFW := firewall(t, fmt.Sprintf(`"webAdmin":{"port":%d,"verifyCertificate":true}`, port))
	if c := byID(t, p.Probe(context.Background(), strictFW), "webadmin"); c.Status != model.HealthCritical || !strings.Contains(c.Message, "certificate") {
		t.Fatalf("%+v", c)
	}
}

// fakeProxy is a forward proxy: absolute-URI requests are answered by
// handler, CONNECT is tunnelled to wherever it asks.
func fakeProxy(t *testing.T, wantAuth string, handler http.HandlerFunc) (port int, connects *atomic.Int32) {
	t.Helper()
	connects = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantAuth != "" && r.Header.Get("Proxy-Authorization") != wantAuth {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if r.Method != http.MethodConnect {
			if !r.URL.IsAbs() {
				http.Error(w, "not a proxy request", 400)
				return
			}
			handler(w, r)
			return
		}
		connects.Add(1)
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, conn); up.Close() }()
		go func() { _, _ = io.Copy(conn, up); conn.Close() }()
	}))
	t.Cleanup(srv.Close)
	return portOf(t, srv.URL), connects
}

func TestProxy(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	port, connects := fakeProxy(t, "", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Host {
		case "blocked.example":
			w.WriteHeader(403)
		case "slow.example":
			time.Sleep(120 * time.Millisecond)
			w.WriteHeader(200)
		case "moved.example":
			http.Redirect(w, r, "http://elsewhere.example/", 302)
		default:
			w.WriteHeader(200)
		}
	})
	fw := firewall(t, fmt.Sprintf(`"proxy":{"port":%d,"warnLatency":"100ms","urls":["http://ok.example/x","http://blocked.example/","http://slow.example/","http://moved.example/","%s/"]}`, port, origin.URL))
	r := (&Prober{}).Probe(context.Background(), fw)
	if len(r.Checks) != 5 {
		t.Fatalf("%+v", r.Checks)
	}
	if c := byID(t, r, "proxy/http://ok.example/x"); c.Status != model.HealthOK || c.Name != "Proxy to http://ok.example" || c.LatencyMs == nil {
		t.Fatalf("%+v", c)
	}
	if c := byID(t, r, "proxy/http://blocked.example/"); c.Status != model.HealthCritical || !strings.Contains(c.Message, "403") {
		t.Fatalf("%+v", c)
	}
	if c := byID(t, r, "proxy/http://slow.example/"); c.Status != model.HealthWarning || !strings.Contains(c.Message, "warns from 100 ms") {
		t.Fatalf("%+v", c)
	}
	// A redirect is an answer and is not followed.
	if c := byID(t, r, "proxy/http://moved.example/"); c.Status != model.HealthOK || !strings.Contains(c.Message, "302") {
		t.Fatalf("%+v", c)
	}
	// https goes through CONNECT.
	if c := byID(t, r, "proxy/"+origin.URL+"/"); c.Status != model.HealthOK || !strings.Contains(c.Message, "204") || connects.Load() != 1 {
		t.Fatalf("%+v connects=%d", c, connects.Load())
	}
	if r.Metrics.ProxyLatencyMs == nil || *r.Metrics.ProxyLatencyMs < 100 {
		t.Fatalf("proxy latency %v", r.Metrics.ProxyLatencyMs)
	}

	// expectStatus overrides what counts as working.
	fw = firewall(t, fmt.Sprintf(`"proxy":{"port":%d,"expectStatus":[403],"urls":["http://blocked.example/","http://ok.example/"]}`, port))
	r = (&Prober{}).Probe(context.Background(), fw)
	if r.Checks[0].Status != model.HealthOK || r.Checks[1].Status != model.HealthCritical {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestProxyAuthAndDown(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer origin.Close()
	port, _ := fakeProxy(t, "Basic dXNlcjpzM2NyZXQ=", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }) // user:s3cret
	urls := fmt.Sprintf(`"urls":["http://ok.example/","%s/"]`, origin.URL)

	r := (&Prober{}).Probe(context.Background(), firewall(t, fmt.Sprintf(`"proxy":{"port":%d,%s}`, port, urls)))
	for _, c := range r.Checks {
		if c.Status != model.HealthCritical || !strings.Contains(c.Message, "407") {
			t.Fatalf("without credentials: %+v", c)
		}
	}
	r = (&Prober{}).Probe(context.Background(), firewall(t, fmt.Sprintf(`"proxy":{"port":%d,"username":"user","password":"s3cret",%s}`, port, urls)))
	for _, c := range r.Checks {
		if c.Status != model.HealthOK {
			t.Fatalf("with credentials: %+v", c)
		}
	}

	// Nothing listening: retried, then critical, and no secret in the text.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	fw := firewall(t, fmt.Sprintf(`"proxy":{"port":%d,"username":"user","password":"s3cret","urls":["http://ok.example/"]}`, dead))
	two := 2
	fw.Retries = &two
	p := &Prober{retryPause: time.Millisecond}
	c := p.Probe(context.Background(), fw).Checks[0]
	if c.Status != model.HealthCritical || !strings.Contains(c.Message, "refused") || strings.Contains(c.Message, "s3cret") {
		t.Fatalf("%+v", c)
	}
}

func TestRetry(t *testing.T) {
	fw := firewall(t, `"tcp":{"ports":[1]}`)
	three := 3
	fw.Retries = &three
	p := &Prober{retryPause: time.Millisecond}
	n := 0
	c := p.retry(context.Background(), fw, func() model.Check {
		n++
		if n < 3 {
			return mk("tcp", "x", "x", model.HealthCritical, "down")
		}
		return mk("tcp", "x", "x", model.HealthOK, "up")
	})
	if n != 3 || c.Status != model.HealthOK {
		t.Fatalf("n=%d %+v", n, c)
	}
	n = 0
	c = p.retry(context.Background(), fw, func() model.Check { n++; return mk("tcp", "x", "x", model.HealthCritical, "down") })
	if n != 4 || c.Status != model.HealthCritical {
		t.Fatalf("n=%d %+v", n, c)
	}
	// A warning is a result, not a failure to retry.
	n = 0
	p.retry(context.Background(), fw, func() model.Check { n++; return mk("tcp", "x", "x", model.HealthWarning, "slow") })
	if n != 1 {
		t.Fatalf("n=%d", n)
	}
}

// fakeSNMP answers from a table.
type fakeSNMP struct {
	vals    map[string]any
	failGet map[string]bool // by first OID of the request
	getErr  error
	closed  bool
}

func (f *fakeSNMP) Get(oids []string) (map[string]any, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.failGet[oids[0]] {
		return nil, errors.New("request timeout (after 1 retries)")
	}
	out := map[string]any{}
	for _, o := range oids {
		if v, ok := f.vals[o]; ok {
			out[o] = v
		}
	}
	return out, nil
}
func (f *fakeSNMP) Walk(root string) (map[string]any, error) {
	out := map[string]any{}
	for o, v := range f.vals {
		if strings.HasPrefix(o, root+".") {
			out[o] = v
		}
	}
	return out, nil
}
func (f *fakeSNMP) Close() error { f.closed = true; return nil }

func healthySNMP() *fakeSNMP {
	v := map[string]any{
		oidDeviceName: "syd-fw01", oidDeviceType: "XGS2100", oidFirmware: "SFOS 21.5.0 GA-Build171", oidAppKey: "X21012ABCDEF", oidWebcatVersion: "1.0.19", oidIPSVersion: "19.1.4",
		oidUpTime: int64(8640000), oidDiskMB: int64(120000), oidDiskPercent: int64(41), oidMemMB: int64(7900), oidMemPercent: int64(62),
		oidSwapMB: int64(3900), oidSwapPercent: int64(3), oidLiveUsers: int64(214),
		oidProcessorLoad + ".196608": int64(10), oidProcessorLoad + ".196609": int64(31),
		oidHA + ".1.0": int64(1), oidHA + ".3.0": "X21012PEER", oidHA + ".4.0": int64(3), oidHA + ".5.0": int64(1), oidHA + ".6.0": "Active-Passive",
	}
	for i := range config.ServiceNames {
		v[fmt.Sprintf("%s.%d.0", oidServices, i+1)] = int64(3)
	}
	v[oidServices+".1.0"] = int64(1) // pop3 stopped
	v[oidServices+".2.0"] = int64(0) // imap4 untouched
	for i := range config.LicenseNames {
		v[fmt.Sprintf("%s.%d.1.0", oidLicenses, i+1)] = int64(3)
		v[fmt.Sprintf("%s.%d.2.0", oidLicenses, i+1)] = "Dec 31 2030"
	}
	v[oidLicenses+".4.1.0"] = int64(2) // mail not subscribed
	v[oidLicenses+".4.2.0"] = "fail"
	return &fakeSNMP{vals: v}
}

func snmpProber(f *fakeSNMP, err error) *Prober {
	return &Prober{
		retryPause: time.Millisecond,
		Now:        func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) },
		NewSNMP: func(context.Context, string, *config.SNMP, time.Duration) (SNMPClient, error) {
			if err != nil {
				return nil, err
			}
			return f, nil
		},
	}
}

func TestSNMPHealthy(t *testing.T) {
	f := healthySNMP()
	r := snmpProber(f, nil).Probe(context.Background(), firewall(t, `"snmp":{"community":"c","requiredServices":["http","dns"],"expectHa":"primary"}`))
	for _, c := range r.Checks {
		if c.Status != model.HealthOK {
			t.Errorf("%+v", c)
		}
	}
	var ids []string
	for _, c := range r.Checks {
		ids = append(ids, c.ID)
	}
	if got := strings.Join(ids, " "); got != "snmp snmp/cpu snmp/memory snmp/swap snmp/disk snmp/services snmp/ha snmp/licenses" {
		t.Fatal(got)
	}
	if !f.closed {
		t.Error("session left open")
	}
	d, m := r.Device, r.Metrics
	if d.Hostname != "syd-fw01" || d.Model != "XGS2100" || !strings.Contains(d.Firmware, "21.5") || d.AppKey != "X21012ABCDEF" {
		t.Fatalf("%+v", d)
	}
	// CPU is the mean of the processors, rounded: (10+31)/2.
	if *m.CPUPercent != 21 || *m.MemoryPercent != 62 || *m.DiskPercent != 41 || *m.LiveUsers != 214 || *m.UptimeSeconds != 86400 || *m.MemoryMB != 7900 {
		t.Fatalf("%+v", m)
	}
	if r.HA == nil || !r.HA.Enabled || r.HA.State != "primary" || r.HA.PeerState != "auxiliary" || r.HA.Mode != "Active-Passive" {
		t.Fatalf("%+v", r.HA)
	}
	if len(r.Services) != 21 || r.Services[0] != (model.Service{Name: "pop3", Status: "stopped"}) || r.Services[4].Status != "running" {
		t.Fatalf("%+v", r.Services)
	}
	if c := byID(t, r, "snmp/services"); c.Message != "19 services running" {
		t.Fatal(c.Message)
	}
	if len(r.Licenses) != 9 || r.Licenses[3].Status != "notsubscribed" || r.Licenses[3].ExpiresAt != nil || r.Licenses[0].ExpiresAt == nil || r.Licenses[0].ExpiresAt.Year() != 2030 {
		t.Fatalf("%+v", r.Licenses)
	}
	if c := byID(t, r, "snmp/licenses"); c.Message != "8 subscriptions active" {
		t.Fatal(c.Message)
	}
}

func TestSNMPProblems(t *testing.T) {
	f := healthySNMP()
	v := f.vals
	v[oidMemPercent] = int64(97)
	v[oidDiskPercent] = int64(84)
	v[oidProcessorLoad+".196608"] = int64(100)
	v[oidProcessorLoad+".196609"] = int64(98)
	v[oidSwapMB] = int64(0) // no swap: not checked
	v[oidSwapPercent] = int64(100)
	v[oidServices+".5.0"] = int64(1)  // http stopped, and required
	v[oidServices+".10.0"] = int64(5) // ips dead
	v[oidServices+".3.0"] = int64(6)  // smtp frozen, but ignored
	v[oidHA+".4.0"] = int64(1)        // this node is now auxiliary
	v[oidHA+".5.0"] = int64(3)
	v[oidLicenses+".3.1.0"] = int64(4) // web expired
	v[oidLicenses+".2.2.0"] = "Dec  4 2026"
	v[oidLicenses+".5.1.0"] = int64(4) // webserver expired, but ignored
	r := snmpProber(f, nil).Probe(context.Background(), firewall(t, `"snmp":{"community":"c","requiredServices":["http"],"ignoreServices":["smtp"],"ignoreLicenses":["webserver"],"expectHa":"primary"}`))

	want := map[string][2]string{
		"snmp":          {model.HealthOK, "answered"},
		"snmp/cpu":      {model.HealthCritical, "99% busy (critical from 95%)"},
		"snmp/memory":   {model.HealthCritical, "97% used (critical from 95%)"},
		"snmp/disk":     {model.HealthWarning, "84% used (warns from 80%)"},
		"snmp/services": {model.HealthCritical, "http is stopped, ips is dead"},
		"snmp/ha":       {model.HealthWarning, "this node is auxiliary, expected primary"},
		"snmp/licenses": {model.HealthCritical, "web has expired, network expires in 10 days"},
	}
	if len(r.Checks) != len(want) {
		t.Fatalf("%+v", r.Checks)
	}
	for id, w := range want {
		if c := byID(t, r, id); c.Status != w[0] || !strings.Contains(c.Message, w[1]) {
			t.Errorf("%s: %s %q, want %s %q", id, c.Status, c.Message, w[0], w[1])
		}
	}

	v[oidHA+".4.0"] = int64(3)
	v[oidHA+".5.0"] = int64(4)
	r = snmpProber(f, nil).Probe(context.Background(), firewall(t, `"snmp":{"community":"c"}`))
	if c := byID(t, r, "snmp/ha"); c.Status != model.HealthCritical || !strings.Contains(c.Message, "peer is faulty") {
		t.Fatalf("%+v", c)
	}
	v[oidHA+".1.0"] = int64(0)
	r = snmpProber(f, nil).Probe(context.Background(), firewall(t, `"snmp":{"community":"c"}`))
	if c := byID(t, r, "snmp/ha"); c.Status != model.HealthOK || c.Message != "HA is off" {
		t.Fatalf("%+v", c)
	}
}

func TestSNMPFailures(t *testing.T) {
	fw := firewall(t, `"snmp":{"community":"c"}`)
	one := 1
	fw.Retries = &one

	// No session, and no answer: one critical check, nothing else.
	for _, p := range []*Prober{snmpProber(nil, errors.New("dial udp: no route")), snmpProber(&fakeSNMP{getErr: errors.New("request timeout (after 1 retries)")}, nil)} {
		r := p.Probe(context.Background(), fw)
		if len(r.Checks) != 1 || r.Checks[0].ID != "snmp" || r.Checks[0].Status != model.HealthCritical || r.Device != nil || !r.Metrics.Empty() {
			t.Fatalf("%+v", r)
		}
	}

	// Answers, but is not a Sophos firewall.
	r := snmpProber(&fakeSNMP{vals: map[string]any{}}, nil).Probe(context.Background(), fw)
	if len(r.Checks) != 1 || r.Checks[0].Status != model.HealthWarning || !strings.Contains(r.Checks[0].Message, "without the Sophos Firewall MIB") {
		t.Fatalf("%+v", r.Checks)
	}

	// The services request fails: the rest stands, snmp warns.
	f := healthySNMP()
	f.failGet = map[string]bool{oidServices + ".1.0": true}
	r = snmpProber(f, nil).Probe(context.Background(), fw)
	if c := byID(t, r, "snmp"); c.Status != model.HealthWarning || !strings.Contains(c.Message, "could not read services") {
		t.Fatalf("%+v", c)
	}
	for _, c := range r.Checks {
		if c.ID == "snmp/services" {
			t.Fatal("services check from a failed request")
		}
	}
	byID(t, r, "snmp/licenses")
	byID(t, r, "snmp/memory")
}

func TestParseDate(t *testing.T) {
	for _, s := range []string{"Dec 31 2030", "Dec  4 2026", "Dec 4, 2026", "2026-12-04", "4 Dec 2026"} {
		if parseDate(s) == nil {
			t.Errorf("%q not read", s)
		}
	}
	for _, s := range []string{"", "fail", "Perpetual"} {
		if parseDate(s) != nil {
			t.Errorf("%q read as a date", s)
		}
	}
}
