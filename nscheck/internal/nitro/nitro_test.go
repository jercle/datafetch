package nitro_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jercle/datafetch/nscheck/internal/nitro"
	"github.com/jercle/datafetch/nscheck/internal/nitrotest"
)

func client(t *testing.T, a *nitrotest.Appliance, pass string) *nitro.Client {
	t.Helper()
	c, err := nitro.New(nitro.Options{Address: a.URL, Username: a.User, Password: pass, Timeout: 5 * time.Second, SkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSessionAndShapes(t *testing.T) {
	for _, bodyToken := range []bool{false, true} {
		a := nitrotest.New()
		a.BodyToken = bodyToken
		a.Set("stat/lbvserver", `[{"name": "lb_web", "state": "UP", "vslbhealth": "100", "primaryport": 443, "actsvcs": "2"}]`)
		a.Set("stat/system", `{"cpuusagepcnt": 12.5, "memusagepcnt": "41.20", "numcpus": "2"}`)
		a.Set("config/Interface", `[{"id": "0/1", "linkstate": 1, "hamonitor": "ON"}, {"id": "1/1", "linkstate": "0", "state": "DISABLED"}]`)
		ctx := context.Background()
		c := client(t, a, a.Pass)

		// Without a session the appliance refuses.
		var ne *nitro.Error
		if _, err := c.Get(ctx, "stat", "system"); !errors.As(err, &ne) || !ne.Denied() || ne.Code != 444 {
			t.Fatalf("bodyToken=%v: before login: %v", bodyToken, err)
		}
		if err := c.Login(ctx); err != nil {
			t.Fatalf("bodyToken=%v: login: %v", bodyToken, err)
		}
		lb, err := c.Get(ctx, "stat", "lbvserver")
		if err != nil || len(lb) != 1 {
			t.Fatalf("lbvserver: %v %v", lb, err)
		}
		if h, ok := lb[0].Num("vslbhealth"); !ok || h != 100 || lb[0].Int("primaryport") != 443 || lb[0].Int("actsvcs") != 2 || lb[0].Str("state") != "UP" {
			t.Fatalf("lbvserver fields: %v", lb[0])
		}
		// A single object comes back as a list of one; numbers may be strings.
		sys, err := c.Get(ctx, "stat", "system")
		if err != nil || len(sys) != 1 {
			t.Fatalf("system: %v %v", sys, err)
		}
		if m, _ := sys[0].Num("memusagepcnt"); m != 41.2 || sys[0].Int("numcpus") != 2 || sys[0].Has("nope") {
			t.Fatalf("system fields: %v", sys[0])
		}
		// The resource name is matched whatever its case.
		ifs, err := c.Get(ctx, "config", "Interface")
		if err != nil || len(ifs) != 2 || !ifs[0].Truthy("linkstate") || ifs[1].Truthy("linkstate") || !ifs[0].Truthy("hamonitor") {
			t.Fatalf("interfaces: %v %v", ifs, err)
		}
		// Nothing configured: no key in the reply, an empty list here.
		if none, err := c.Get(ctx, "stat", "gslbvserver"); err != nil || len(none) != 0 {
			t.Fatalf("empty resource: %v %v", none, err)
		}
		a.Fail("stat/csvserver", http.StatusBadRequest)
		if _, err := c.Get(ctx, "stat", "csvserver"); !errors.As(err, &ne) || !ne.Answered() || ne.Denied() || ne.Code != 1097 {
			t.Fatalf("failing resource: %v", err)
		}
		c.Logout(ctx)
		if a.OpenSessions() != 0 || a.Logins != 1 || a.Logouts != 1 {
			t.Fatalf("bodyToken=%v: sessions left open: %d", bodyToken, a.OpenSessions())
		}
		if _, err := c.Get(ctx, "stat", "system"); err == nil {
			t.Fatal("the session should be gone after logout")
		}
		a.Close()
	}
}

func TestLoginFailures(t *testing.T) {
	a := nitrotest.New()
	var ne *nitro.Error
	err := client(t, a, "wrong").Login(context.Background())
	if !errors.As(err, &ne) || !ne.Denied() || ne.Code != 354 || ne.Message != "Invalid username or password" {
		t.Fatalf("wrong password: %v", err)
	}
	// A certificate that does not verify is refused unless asked otherwise.
	strict, _ := nitro.New(nitro.Options{Address: a.URL, Username: a.User, Password: a.Pass, Timeout: 5 * time.Second})
	if err := strict.Login(context.Background()); !errors.As(err, &ne) || ne.Answered() {
		t.Fatalf("untrusted certificate: %v", err)
	}
	a.Close()
	// Nothing listening: an error that was not answered.
	if err := client(t, a, a.Pass).Login(context.Background()); !errors.As(err, &ne) || ne.Answered() {
		t.Fatalf("unreachable: %v", err)
	}
}
