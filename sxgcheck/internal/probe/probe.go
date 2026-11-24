// Package probe makes the checks on one firewall: TCP ports, certificates,
// the web admin console, requests through the web proxy, the XML API and the
// SFOS MIB over SNMP.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jercle/datafetch/sxgcheck/internal/config"
	"github.com/jercle/datafetch/sxgcheck/internal/model"
)

// Result is everything one pass learned about a firewall. The checks carry
// no Since; the checker sets it.
type Result struct {
	Checks   []model.Check
	Device   *model.Device
	Metrics  model.Metrics
	HA       *model.HA
	Services []model.Service
	Licenses []model.License
}

// Prober runs the checks.
type Prober struct {
	// NewSNMP opens an SNMP session. Default: NewGoSNMP.
	NewSNMP func(ctx context.Context, host string, s *config.SNMP, timeout time.Duration) (SNMPClient, error)
	// Now is the clock. Default: time.Now.
	Now func() time.Time
	// retryPause is the wait between attempts. Default 500ms.
	retryPause time.Duration
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Probe makes every configured check on the firewall, the kinds side by
// side. The checks come back in a fixed order.
func (p *Prober) Probe(ctx context.Context, fw config.Firewall) Result {
	var (
		wg                                 sync.WaitGroup
		tcp, tlsC, web, proxy, api, snmpCk []model.Check
		res                                Result
		apiVersion                         string
	)
	run := func(on bool, fn func()) {
		if !on {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	run(fw.TCPOn(), func() {
		tcp = p.each(len(fw.TCP.Ports), func(i int) model.Check {
			return p.retry(ctx, fw, func() model.Check { return checkTCP(ctx, fw, fw.TCP.Ports[i]) })
		})
	})
	run(fw.TLSOn(), func() {
		tlsC = p.each(len(fw.TLS.Ports), func(i int) model.Check {
			return p.retry(ctx, fw, func() model.Check { return checkTLS(ctx, fw, fw.TLS.Ports[i], p.now()) })
		})
	})
	run(fw.WebAdminOn(), func() { web = []model.Check{p.retry(ctx, fw, func() model.Check { return checkWebAdmin(ctx, fw) })} })
	run(fw.ProxyOn(), func() {
		proxy = p.each(len(fw.Proxy.URLs), func(i int) model.Check {
			return p.retry(ctx, fw, func() model.Check { return checkProxy(ctx, fw, fw.Proxy.URLs[i]) })
		})
	})
	run(fw.APIOn(), func() {
		api = []model.Check{p.retry(ctx, fw, func() model.Check {
			c, v := checkAPI(ctx, fw)
			apiVersion = v
			return c
		})}
	})
	run(fw.SNMPOn(), func() {
		var r Result
		for i := 0; i < fw.Attempts(); i++ {
			r = p.checkSNMP(ctx, fw)
			if r.Checks[0].Status != model.HealthCritical || !p.pause(ctx, i, fw.Attempts()) {
				break
			}
		}
		snmpCk = r.Checks
		res.Device, res.Metrics, res.HA, res.Services, res.Licenses = r.Device, r.Metrics, r.HA, r.Services, r.Licenses
	})
	wg.Wait()

	for _, list := range [][]model.Check{tcp, tlsC, web, proxy, api, snmpCk} {
		res.Checks = append(res.Checks, list...)
	}
	if apiVersion != "" {
		if res.Device == nil {
			res.Device = &model.Device{}
		}
		res.Device.APIVersion = apiVersion
	}
	// The slowest request that got through the proxy.
	for _, c := range proxy {
		if c.Status != model.HealthCritical && c.LatencyMs != nil && (res.Metrics.ProxyLatencyMs == nil || *c.LatencyMs > *res.Metrics.ProxyLatencyMs) {
			res.Metrics.ProxyLatencyMs = c.LatencyMs
		}
	}
	return res
}

// each runs fn for 0..n-1 side by side and keeps the order.
func (p *Prober) each(n int, fn func(i int) model.Check) []model.Check {
	out := make([]model.Check, n)
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = fn(i)
		}()
	}
	wg.Wait()
	return out
}

// pause waits before the next attempt. It reports false when there is none.
func (p *Prober) pause(ctx context.Context, attempt, attempts int) bool {
	if attempt+1 >= attempts {
		return false
	}
	d := p.retryPause
	if d == 0 {
		d = 500 * time.Millisecond
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// retry repeats a check that came back critical, so one lost packet does not
// raise an alarm.
func (p *Prober) retry(ctx context.Context, fw config.Firewall, fn func() model.Check) model.Check {
	var c model.Check
	for i := 0; ; i++ {
		c = fn()
		if c.Status != model.HealthCritical || !p.pause(ctx, i, fw.Attempts()) {
			return c
		}
	}
}

func mk(kind, id, name, status, message string) model.Check {
	return model.Check{ID: id, Kind: kind, Name: name, Status: status, Message: message}
}

func ms(d time.Duration) *int64 {
	v := d.Milliseconds()
	return &v
}

func f64(v float64) *float64 { return &v }

// reason words an error for the dashboard.
func reason(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return "timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		var dns *net.DNSError
		if errors.As(op.Err, &dns) {
			return "the name " + dns.Name + " does not resolve"
		}
		return unwrapSyscall(op.Err)
	}
	return err.Error()
}

func unwrapSyscall(err error) string {
	var se *os.SyscallError
	if errors.As(err, &se) {
		return se.Err.Error()
	}
	return err.Error()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
