package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jercle/datafetch/sxgcheck/internal/config"
	"github.com/jercle/datafetch/sxgcheck/internal/model"
)

const userAgent = "sxg-check"

func addr(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// checkTCP connects to a port and hangs up.
func checkTCP(ctx context.Context, fw config.Firewall, port int) model.Check {
	c := mk(model.KindTCP, fmt.Sprintf("tcp/%d", port), fmt.Sprintf("TCP %d", port), model.HealthOK, "")
	d := net.Dialer{Timeout: fw.Timeout.D()}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr(fw.Host, port))
	if err != nil {
		c.Status, c.Message = model.HealthCritical, "not reachable: "+reason(err)
		return c
	}
	_ = conn.Close()
	took := time.Since(start)
	c.LatencyMs, c.Message = ms(took), fmt.Sprintf("open, connected in %d ms", took.Milliseconds())
	return c
}

// checkTLS reads the certificate a port presents and checks its dates. The
// chain is deliberately not verified: a self-signed console certificate
// still expires.
func checkTLS(ctx context.Context, fw config.Firewall, port int, now time.Time) model.Check {
	c := mk(model.KindTLS, fmt.Sprintf("tls/%d", port), fmt.Sprintf("Certificate on %d", port), model.HealthOK, "")
	name := fw.TLS.ServerName
	if name == "" && net.ParseIP(fw.Host) == nil {
		name = fw.Host
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: fw.Timeout.D()}, Config: &tls.Config{InsecureSkipVerify: true, ServerName: name}} //nolint:gosec // only the dates are read
	dctx, cancel := context.WithTimeout(ctx, fw.Timeout.D())
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", addr(fw.Host, port))
	if err != nil {
		c.Status, c.Message = model.HealthCritical, "no TLS handshake: "+reason(err)
		return c
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		c.Status, c.Message = model.HealthCritical, "no certificate presented"
		return c
	}
	cert := certs[0]
	subject := cert.Subject.CommonName
	if subject == "" && len(cert.DNSNames) > 0 {
		subject = cert.DNSNames[0]
	}
	days := math.Floor(cert.NotAfter.Sub(now).Hours() / 24)
	c.Value, c.Unit = f64(days), "days"
	until := cert.NotAfter.UTC().Format("2006-01-02")
	switch {
	case now.Before(cert.NotBefore):
		c.Status, c.Message = model.HealthCritical, fmt.Sprintf("certificate %q is not valid until %s", subject, cert.NotBefore.UTC().Format("2006-01-02"))
	case days < 0:
		c.Status, c.Message = model.HealthCritical, fmt.Sprintf("certificate %q expired on %s", subject, until)
	case int(days) <= fw.TLS.CriticalDays:
		c.Status, c.Message = model.HealthCritical, fmt.Sprintf("certificate %q expires in %s (%s)", subject, plural(int(days), "day", "days"), until)
	case int(days) <= fw.TLS.WarnDays:
		c.Status, c.Message = model.HealthWarning, fmt.Sprintf("certificate %q expires in %s (%s)", subject, plural(int(days), "day", "days"), until)
	default:
		c.Message = fmt.Sprintf("certificate %q is valid for %d more days (%s)", subject, int(days), until)
	}
	return c
}

func httpClient(timeout time.Duration, verify bool, proxy *url.URL, connectHeader http.Header) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives:     true,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !verify}, //nolint:gosec // set by verifyCertificate
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		ProxyConnectHeader:    connectHeader,
	}
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   3 * timeout,
		// A redirect is an answer; where it leads is not being checked.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// httpReason words a client error without the URL in front of it.
func httpReason(err error) string {
	if ue, ok := err.(*url.Error); ok {
		if ue.Timeout() {
			return "timed out"
		}
		err = ue.Err
	}
	return reason(err)
}

// checkWebAdmin asks the web admin console for its front page.
func checkWebAdmin(ctx context.Context, fw config.Firewall) model.Check {
	w := fw.WebAdmin
	c := mk(model.KindWebAdmin, "webadmin", "Web admin console", model.HealthOK, "")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr(fw.Host, w.Port)+"/", nil)
	req.Header.Set("User-Agent", userAgent)
	client := httpClient(fw.Timeout.D(), w.VerifyCertificate, nil, nil)
	defer client.CloseIdleConnections()
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		c.Status, c.Message = model.HealthCritical, "no answer: "+httpReason(err)
		return c
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	took := time.Since(start)
	c.LatencyMs = ms(took)
	if resp.StatusCode >= 500 {
		c.Status, c.Message = model.HealthCritical, fmt.Sprintf("answered HTTP %d", resp.StatusCode)
		return c
	}
	c.Message = fmt.Sprintf("answered HTTP %d in %d ms", resp.StatusCode, took.Milliseconds())
	return c
}

// checkProxy requests a URL through the firewall's web proxy.
func checkProxy(ctx context.Context, fw config.Firewall, target string) model.Check {
	p := fw.Proxy
	u, _ := url.Parse(target)
	c := mk(model.KindProxy, "proxy/"+target, "Proxy to "+u.Scheme+"://"+u.Host, model.HealthOK, "")
	// The credentials go in headers, not in the proxy URL, so they cannot
	// end up in an error message.
	var auth string
	connect := http.Header{"User-Agent": {userAgent}}
	if p.Username != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(p.Username+":"+p.Password))
		connect.Set("Proxy-Authorization", auth)
	}
	client := httpClient(fw.Timeout.D(), p.VerifyCertificate, &url.URL{Scheme: "http", Host: addr(fw.Host, p.Port)}, connect)
	defer client.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Cache-Control", "no-cache")
	if auth != "" && u.Scheme == "http" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		msg := httpReason(err)
		if strings.Contains(msg, "Proxy Authentication Required") {
			msg = "the proxy asked for authentication (HTTP 407)"
		}
		c.Status, c.Message = model.HealthCritical, "no answer through the proxy: "+msg
		return c
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	took := time.Since(start)
	c.LatencyMs, c.Value, c.Unit = ms(took), f64(float64(took.Milliseconds())), "ms"

	good := resp.StatusCode >= 200 && resp.StatusCode < 400
	if len(p.ExpectStatus) > 0 {
		good = false
		for _, s := range p.ExpectStatus {
			good = good || s == resp.StatusCode
		}
	}
	switch {
	case !good && resp.StatusCode == http.StatusProxyAuthRequired:
		c.Status, c.Message = model.HealthCritical, "the proxy asked for authentication (HTTP 407)"
	case !good && resp.StatusCode == http.StatusForbidden:
		c.Status, c.Message = model.HealthCritical, "refused or blocked by the proxy (HTTP 403)"
	case !good:
		c.Status, c.Message = model.HealthCritical, fmt.Sprintf("answered HTTP %d", resp.StatusCode)
	case p.CriticalLatency > 0 && took >= p.CriticalLatency.D():
		c.Status, c.Message = model.HealthCritical, fmt.Sprintf("HTTP %d, but it took %d ms (critical from %d ms)", resp.StatusCode, took.Milliseconds(), p.CriticalLatency.D().Milliseconds())
	case p.WarnLatency > 0 && took >= p.WarnLatency.D():
		c.Status, c.Message = model.HealthWarning, fmt.Sprintf("HTTP %d, but it took %d ms (warns from %d ms)", resp.StatusCode, took.Milliseconds(), p.WarnLatency.D().Milliseconds())
	default:
		c.Message = fmt.Sprintf("HTTP %d in %d ms", resp.StatusCode, took.Milliseconds())
	}
	return c
}

// apiResponse is the part of an XML API answer the check reads.
type apiResponse struct {
	XMLName    xml.Name `xml:"Response"`
	APIVersion string   `xml:"APIVersion,attr"`
	Login      struct {
		Status string `xml:"status"`
	} `xml:"Login"`
	// Some versions put the login status at the top level.
	TopStatus string `xml:"status"`
	Statuses  []struct {
		Code string `xml:"code,attr"`
		Text string `xml:",chardata"`
	} `xml:"Status"`
}

// checkAPI signs in to the XML API. It reads nothing and changes nothing: the
// request holds only the Login block. It returns the API version too.
func checkAPI(ctx context.Context, fw config.Firewall) (model.Check, string) {
	a := fw.API
	c := mk(model.KindAPI, "api", "XML API sign-in", model.HealthOK, "")
	var user, pass bytes.Buffer
	_ = xml.EscapeText(&user, []byte(a.Username))
	_ = xml.EscapeText(&pass, []byte(a.Password))
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	_ = form.WriteField("reqxml", "<Request><Login><Username>"+user.String()+"</Username><Password>"+pass.String()+"</Password></Login></Request>")
	_ = form.Close()

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr(fw.Host, a.Port)+"/webconsole/APIController", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set("User-Agent", userAgent)
	client := httpClient(fw.Timeout.D(), a.VerifyCertificate, nil, nil)
	defer client.CloseIdleConnections()
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		c.Status, c.Message = model.HealthCritical, "no answer: "+httpReason(err)
		return c, ""
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	_ = resp.Body.Close()
	took := time.Since(start)
	c.LatencyMs = ms(took)
	if resp.StatusCode != http.StatusOK {
		c.Status, c.Message = model.HealthCritical, fmt.Sprintf("answered HTTP %d", resp.StatusCode)
		return c, ""
	}
	var r apiResponse
	if err := xml.Unmarshal(raw, &r); err != nil {
		c.Status, c.Message = model.HealthCritical, "the answer is not an XML API response"
		return c, ""
	}
	login := strings.TrimSpace(r.Login.Status)
	if login == "" {
		login = strings.TrimSpace(r.TopStatus)
	}
	switch {
	case strings.Contains(login, "Successful"):
		c.Message = fmt.Sprintf("signed in as %s in %d ms", a.Username, took.Milliseconds())
		if r.APIVersion != "" {
			c.Message += ", API version " + r.APIVersion
		}
	case login != "":
		c.Status, c.Message = model.HealthCritical, "sign-in refused: "+login
	case len(r.Statuses) > 0:
		// For example: API access is off, or this address is not allowed.
		c.Status, c.Message = model.HealthCritical, strings.TrimSpace(r.Statuses[0].Text)
		if r.Statuses[0].Code != "" {
			c.Message += " (code " + r.Statuses[0].Code + ")"
		}
	default:
		c.Status, c.Message = model.HealthCritical, "the answer has no sign-in status"
	}
	return c, r.APIVersion
}
