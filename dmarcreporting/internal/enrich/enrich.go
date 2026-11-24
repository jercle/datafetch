// Package enrich adds geolocation, ASN, reverse DNS and organisational
// domains to parsed failure reports.
package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jercle/datafetch/dmarcreporting/internal/model"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/net/publicsuffix"
)

type Options struct {
	CityDB      string
	ASNDB       string
	IPInfoToken string
	ReverseDNS  bool
	DNSTimeout  time.Duration
	CacheTTL    time.Duration
}

type Enricher struct {
	opt      Options
	city     *geoip2.Reader
	asn      *geoip2.Reader
	http     *http.Client
	resolver *net.Resolver
	log      *slog.Logger

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type ipInfo struct {
	geo          *model.Geo
	asn          *model.ASN
	ptr          []string
	ptrConfirmed bool
	ptrOrg       string
}

type cacheEntry struct {
	info ipInfo
	exp  time.Time
}

func New(opt Options, log *slog.Logger) (*Enricher, error) {
	if opt.DNSTimeout == 0 {
		opt.DNSTimeout = 3 * time.Second
	}
	if opt.CacheTTL == 0 {
		opt.CacheTTL = 12 * time.Hour
	}
	e := &Enricher{
		opt:      opt,
		http:     &http.Client{Timeout: 10 * time.Second},
		resolver: net.DefaultResolver,
		log:      log,
		cache:    map[string]cacheEntry{},
	}
	var err error
	if opt.CityDB != "" {
		if e.city, err = geoip2.Open(opt.CityDB); err != nil {
			return nil, fmt.Errorf("open city db: %w", err)
		}
	}
	if opt.ASNDB != "" {
		if e.asn, err = geoip2.Open(opt.ASNDB); err != nil {
			return nil, fmt.Errorf("open asn db: %w", err)
		}
	}
	if e.city == nil && opt.IPInfoToken == "" {
		log.Warn("no GEOIP_CITY_DB or IPINFO_TOKEN configured; reports will not be geolocated")
	}
	return e, nil
}

func (e *Enricher) Close() {
	if e.city != nil {
		e.city.Close()
	}
	if e.asn != nil {
		e.asn.Close()
	}
}

// Enrich never fails: missing enrichment is recorded as a warning.
func (e *Enricher) Enrich(ctx context.Context, r *model.FailureReport) {
	r.ReportedOrgDomain = OrgDomain(r.ReportedDomain)
	r.Original.FromOrgDomain = OrgDomain(r.Original.FromDomain)
	r.Reporter.OrgDomain = OrgDomain(r.Reporter.Domain)

	if w := e.EnrichSource(ctx, &r.Source); w != "" {
		r.Warnings = append(r.Warnings, w)
	}
}

// EnrichSource fills geo/ASN/rDNS for a source IP. Returns a warning or "".
func (e *Enricher) EnrichSource(ctx context.Context, s *model.Source) string {
	if s.IP == "" {
		return ""
	}
	addr, err := netip.ParseAddr(s.IP)
	if err != nil {
		return "invalid source IP"
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		s.IsPrivate = true
		return ""
	}
	info := e.lookup(ctx, addr)
	s.Geo = info.geo
	s.ASN = info.asn
	s.PTR = info.ptr
	s.PTRConfirmed = info.ptrConfirmed
	s.PTROrgDomain = info.ptrOrg
	return ""
}

// EnrichAggregate enriches every record of an aggregate report. Big reports
// can carry thousands of rows, so unique IPs are looked up concurrently.
func (e *Enricher) EnrichAggregate(ctx context.Context, rep *model.AggregateReport, recs []*model.AggregateRecord) {
	rep.ReportedOrgDomain = OrgDomain(rep.ReportedDomain)
	rep.Reporter.OrgDomain = OrgDomain(rep.Reporter.Domain)

	byIP := map[string]*model.Source{}
	for _, r := range recs {
		if r.Source.IP != "" && byIP[r.Source.IP] == nil {
			s := model.Source{IP: r.Source.IP, IPVersion: r.Source.IPVersion}
			byIP[r.Source.IP] = &s
		}
	}
	jobs := make(chan *model.Source)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				e.EnrichSource(ctx, s)
			}
		}()
	}
	for _, s := range byIP {
		jobs <- s
	}
	close(jobs)
	wg.Wait()

	for _, r := range recs {
		r.ReportedOrgDomain = rep.ReportedOrgDomain
		r.Reporter.OrgDomain = rep.Reporter.OrgDomain
		r.HeaderFromOrg = OrgDomain(r.HeaderFrom)
		r.EnvelopeFromOrg = OrgDomain(r.EnvelopeFrom)
		if s := byIP[r.Source.IP]; s != nil {
			r.Source = *s
		}
	}
}

func (e *Enricher) lookup(ctx context.Context, addr netip.Addr) ipInfo {
	key := addr.String()
	e.mu.Lock()
	if c, ok := e.cache[key]; ok && time.Now().Before(c.exp) {
		e.mu.Unlock()
		return c.info
	}
	e.mu.Unlock()

	var info ipInfo
	ip := net.IP(addr.AsSlice())
	if e.city != nil {
		if rec, err := e.city.City(ip); err == nil {
			g := &model.Geo{
				CountryCode:    rec.Country.IsoCode,
				Country:        rec.Country.Names["en"],
				ContinentCode:  rec.Continent.Code,
				City:           rec.City.Names["en"],
				PostalCode:     rec.Postal.Code,
				TimeZone:       rec.Location.TimeZone,
				AccuracyRadius: int(rec.Location.AccuracyRadius),
				Provider:       "maxmind",
			}
			if g.CountryCode == "" {
				g.CountryCode, g.Country = rec.RegisteredCountry.IsoCode, rec.RegisteredCountry.Names["en"]
			}
			if len(rec.Subdivisions) > 0 {
				g.Region = rec.Subdivisions[0].Names["en"]
			}
			if rec.Location.Latitude != 0 || rec.Location.Longitude != 0 {
				lat, lon := rec.Location.Latitude, rec.Location.Longitude
				g.Lat, g.Lon = &lat, &lon
			}
			if g.CountryCode != "" {
				info.geo = g
			}
		}
	}
	if e.asn != nil {
		if a, err := e.asn.ASN(ip); err == nil && a.AutonomousSystemNumber != 0 {
			info.asn = &model.ASN{Number: int(a.AutonomousSystemNumber), Org: a.AutonomousSystemOrganization}
		}
	}
	if (info.geo == nil || info.asn == nil || info.asn.Domain == "") && e.opt.IPInfoToken != "" {
		e.ipinfo(ctx, addr, &info)
	}
	if e.opt.ReverseDNS {
		e.rdns(ctx, addr, &info)
	}

	e.mu.Lock()
	if len(e.cache) > 50_000 {
		e.cache = map[string]cacheEntry{}
	}
	e.cache[key] = cacheEntry{info: info, exp: time.Now().Add(e.opt.CacheTTL)}
	e.mu.Unlock()
	return info
}

// ipinfo uses the free ipinfo Lite API (country + ASN, no city).
func (e *Enricher) ipinfo(ctx context.Context, addr netip.Addr, info *ipInfo) {
	u := "https://api.ipinfo.io/lite/" + url.PathEscape(addr.String()) + "?token=" + url.QueryEscape(e.opt.IPInfoToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.log.Debug("ipinfo lookup failed", "ip", addr, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.log.Debug("ipinfo lookup failed", "ip", addr, "status", resp.StatusCode)
		return
	}
	var r struct {
		ASN           string `json:"asn"`
		ASName        string `json:"as_name"`
		ASDomain      string `json:"as_domain"`
		CountryCode   string `json:"country_code"`
		Country       string `json:"country"`
		ContinentCode string `json:"continent_code"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil {
		return
	}
	if info.geo == nil && r.CountryCode != "" {
		info.geo = &model.Geo{CountryCode: r.CountryCode, Country: r.Country, ContinentCode: r.ContinentCode, Provider: "ipinfo"}
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(r.ASN), "AS"))
	if info.asn == nil && n != 0 {
		info.asn = &model.ASN{Number: n, Org: r.ASName}
	}
	if info.asn != nil && info.asn.Domain == "" && info.asn.Number == n {
		info.asn.Domain = r.ASDomain
	}
}

// rdns looks up PTR records and forward-confirms them (FCrDNS).
func (e *Enricher) rdns(ctx context.Context, addr netip.Addr, info *ipInfo) {
	ctx, cancel := context.WithTimeout(ctx, e.opt.DNSTimeout)
	defer cancel()
	names, err := e.resolver.LookupAddr(ctx, addr.String())
	if err != nil || len(names) == 0 {
		return
	}
	for _, n := range names {
		info.ptr = append(info.ptr, strings.TrimSuffix(strings.ToLower(n), "."))
	}
	if len(info.ptr) > 5 {
		info.ptr = info.ptr[:5]
	}
	info.ptrOrg = OrgDomain(info.ptr[0])
	for _, n := range info.ptr[:min(len(info.ptr), 3)] {
		ips, err := e.resolver.LookupNetIP(ctx, "ip", n)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Unmap() == addr {
				info.ptrConfirmed = true
				return
			}
		}
	}
}

// OrgDomain returns the registrable domain (public suffix + 1).
func OrgDomain(d string) string {
	d = strings.Trim(strings.ToLower(d), ".")
	if d == "" {
		return ""
	}
	if od, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return od
	}
	return d
}
