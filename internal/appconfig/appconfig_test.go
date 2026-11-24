package appconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAudience(t *testing.T) {
	for in, want := range map[string]string{
		"https://contoso.azconfig.io":             "https://azconfig.io",
		"https://contoso.azconfig.azure.us":       "https://azconfig.azure.us",
		"https://kv1.vault.azure.net/secrets/x/1": "https://vault.azure.net",
		"https://kv1.vault.usgovcloudapi.net/":    "https://vault.usgovcloudapi.net",
	} {
		if got := audience(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, ok, err := FromEnv(env(nil)); ok || err != nil {
		t.Error("no endpoint: not configured, no error")
	}
	if _, ok, err := FromEnv(env(map[string]string{"AZURE_APPCONFIG_ENDPOINT": "https://x.azconfig.io/"})); !ok || err == nil {
		t.Error("an endpoint without credentials is an error")
	}
	o, ok, err := FromEnv(env(map[string]string{"AZURE_APPCONFIG_ENDPOINT": "https://x.azconfig.io/", "AZURE_APPCONFIG_MANAGED_IDENTITY": "abc", "AZURE_APPCONFIG_LABEL_FILTER": "staging"}))
	if !ok || err != nil || o.Endpoint != "https://x.azconfig.io" || o.Label != "staging" || o.ManagedIdentity != "abc" {
		t.Errorf("%+v %v", o, err)
	}
}

func TestLoad(t *testing.T) {
	var requests []string
	fail := 1
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		kv := func(key, ct, value string) map[string]any {
			return map[string]any{"key": key, "content_type": ct, "value": value}
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "s" {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"error_description": "AADSTS7000215: Invalid client secret\nTrace"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok:" + r.Form.Get("scope"), "expires_in": 3600})
		case r.URL.Path == "/metadata/identity/oauth2/token":
			if r.Header.Get("Metadata") != "true" {
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "mi:" + r.URL.Query().Get("resource") + ":" + r.URL.Query().Get("client_id"), "expires_in": "3600"})
		case r.URL.Path == "/kv":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || r.URL.Query().Get("key") != "azureDriftChecker.*" {
				w.WriteHeader(401)
				return
			}
			if fail > 0 {
				fail--
				w.WriteHeader(503)
				return
			}
			label := r.URL.Query().Get("label")
			switch {
			case label == "\x00" && r.URL.Query().Get("page") == "":
				_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
					kv("azureDriftChecker.interval", "", "12h"),
					kv("azureDriftChecker.concurrency.tenants", "application/json", "4"),
					kv("azureDriftChecker.logging.level", "text/plain", "info"),
				}, "@nextLink": "/kv?" + r.URL.RawQuery + "&page=2"})
			case label == "\x00":
				_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
					kv("azureDriftChecker.tenants.t1.platforms", "application/json; charset=utf-8", `["azure"]`),
					kv("azureDriftChecker.tenants.t1.clientSecret", "application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8", `{"uri": "`+srv.URL+`/secrets/t1-secret"}`),
					kv("azureDriftChecker.tenants.t1.password", "application/vnd.microsoft.appconfig.keyvaultref+json;charset=utf-8", `{"uri": "`+srv.URL+`/secrets/missing"}`),
					kv("azureDriftChecker.mongo.ensureIndexes", "application/json", "not json"),
				}})
			case label == "staging":
				_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{kv("azureDriftChecker.interval", "", "1h")}})
			}
		case r.URL.Path == "/secrets/t1-secret" && r.URL.Query().Get("api-version") == "7.4":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": "from-key-vault"})
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error": {"code": "SecretNotFound"}}`))
		}
	}))
	defer srv.Close()

	c := New(Options{Endpoint: srv.URL + "/", Label: "staging", TenantID: "t", ClientID: "c", ClientSecret: "s", Authority: srv.URL})
	// A reference to anything but a Key Vault gets no token.
	if _, err := c.secret(context.Background(), `{"uri": "https://evil.example.com/secrets/x"}`); err == nil || !strings.Contains(err.Error(), "not an Azure Key Vault") {
		t.Errorf("a reference outside Key Vault: %v", err)
	}
	if _, err := c.secret(context.Background(), `{"uri": "http://kv.vault.azure.net/secrets/x"}`); err == nil {
		t.Error("a reference over plain HTTP must be refused")
	}
	c.anyVault = true
	requests = nil
	values, warnings, err := c.Load(context.Background(), "azureDriftChecker.")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(values)
	want := `{"azureDriftChecker.concurrency.tenants":4,"azureDriftChecker.interval":"1h","azureDriftChecker.logging.level":"info","azureDriftChecker.mongo.ensureIndexes":"not json","azureDriftChecker.tenants.t1.clientSecret":"from-key-vault","azureDriftChecker.tenants.t1.platforms":["azure"]}`
	if string(b) != want {
		t.Errorf("values:\n%s", b)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "tenants.t1.password: the Key Vault reference could not be read") || strings.Contains(warnings[0], "from-key-vault") {
		t.Errorf("warnings: %v", warnings)
	}
	for _, r := range requests {
		if strings.Contains(r, "evil") || strings.Contains(r, "kv.vault") {
			t.Errorf("unexpected request %s", r)
		}
	}

	// A wrong secret is an error that names no secret.
	bad := New(Options{Endpoint: srv.URL, TenantID: "t", ClientID: "c", ClientSecret: "wrong", Authority: srv.URL})
	if _, _, err := bad.Load(context.Background(), "azureDriftChecker."); err == nil || !strings.Contains(err.Error(), "AADSTS7000215") || strings.Contains(err.Error(), "Trace") {
		t.Errorf("wrong secret: %v", err)
	}

	// A managed identity, through the instance metadata service.
	mi := New(Options{Endpoint: srv.URL, ManagedIdentity: "client-1", IMDS: srv.URL})
	if tok, err := mi.token(context.Background(), "https://azconfig.io"); err != nil || tok != "mi:https://azconfig.io:client-1" {
		t.Errorf("managed identity: %q %v", tok, err)
	}
	sys := New(Options{Endpoint: srv.URL, ManagedIdentity: "system", IMDS: srv.URL})
	if tok, _ := sys.token(context.Background(), "r"); tok != "mi:r:" {
		t.Errorf("system-assigned identity: %q", tok)
	}
}
