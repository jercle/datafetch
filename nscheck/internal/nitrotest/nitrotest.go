// Package nitrotest is a stand-in NetScaler for tests: an HTTP server that
// answers the NITRO calls ns-check makes, from bodies the test sets.
package nitrotest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Appliance is a fake NetScaler. Set and Fail may be called between passes.
type Appliance struct {
	*httptest.Server
	User, Pass string
	// BodyToken makes the login return the session id in the body only,
	// with no cookie, as some firmware does.
	BodyToken bool

	mu       sync.Mutex
	bodies   map[string]string // "stat/system" -> the value of the resource
	fails    map[string]int    // "stat/lbvserver" -> HTTP status
	sessions map[string]bool
	n        int
	calls    []string
	// Logins and Logouts count the sessions opened and closed.
	Logins, Logouts int
}

func New() *Appliance {
	a := &Appliance{User: "nscheck", Pass: "secret", bodies: map[string]string{}, fails: map[string]int{}, sessions: map[string]bool{}}
	a.Server = httptest.NewTLSServer(http.HandlerFunc(a.serve))
	return a
}

// Set gives a resource its value: a JSON list or object, as NITRO returns
// it under the resource's name. An empty value removes the resource from
// the reply, which is how NITRO reports "none".
func (a *Appliance) Set(path, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bodies[path] = value
}

// Fail makes a resource answer with an HTTP status and a NITRO error; 0
// clears it.
func (a *Appliance) Fail(path string, status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if status == 0 {
		delete(a.fails, path)
	} else {
		a.fails[path] = status
	}
}

// Calls returns the resources read since the last call to Calls.
func (a *Appliance) Calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.calls
	a.calls = nil
	return c
}

func (a *Appliance) OpenSessions() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.sessions)
}

func nitroError(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"errorcode": %d, "message": %q, "severity": "ERROR"}`, code, msg)
}

func (a *Appliance) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/nitro/v1/")
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case path == "config/login" && r.Method == http.MethodPost:
		var in struct {
			Login struct{ Username, Password string } `json:"login"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &in)
		if in.Login.Username != a.User || in.Login.Password != a.Pass {
			nitroError(w, http.StatusUnauthorized, 354, "Invalid username or password")
			return
		}
		a.n++
		a.Logins++
		token := fmt.Sprintf("##session%d==", a.n)
		a.sessions[token] = true
		if !a.BodyToken {
			http.SetCookie(w, &http.Cookie{Name: "NITRO_AUTH_TOKEN", Value: strings.NewReplacer("#", "%23", "=", "%3D").Replace(token), Path: "/nitro/v1"})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"errorcode": 0, "message": "Done", "severity": "NONE", "sessionid": %q}`, token)
		return
	}
	token := ""
	if c, err := r.Cookie("NITRO_AUTH_TOKEN"); err == nil {
		token = strings.NewReplacer("%23", "#", "%3D", "=").Replace(c.Value)
	}
	if !a.sessions[token] {
		nitroError(w, http.StatusUnauthorized, 444, "Session expired or killed. Please login again")
		return
	}
	if path == "config/logout" {
		delete(a.sessions, token)
		a.Logouts++
		fmt.Fprint(w, `{"errorcode": 0, "message": "Done", "severity": "NONE"}`)
		return
	}
	if r.Method != http.MethodGet {
		nitroError(w, http.StatusMethodNotAllowed, 1, "read-only")
		return
	}
	a.calls = append(a.calls, path)
	if status := a.fails[path]; status != 0 {
		nitroError(w, status, 1097, "Feature(s) not enabled")
		return
	}
	resource := path[strings.Index(path, "/")+1:]
	w.Header().Set("Content-Type", "application/json")
	if v := a.bodies[path]; v != "" {
		fmt.Fprintf(w, `{"errorcode": 0, "message": "Done", "severity": "NONE", %q: %s}`, resource, v)
		return
	}
	fmt.Fprint(w, `{"errorcode": 0, "message": "Done", "severity": "NONE"}`)
}
