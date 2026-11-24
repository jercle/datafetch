// Package auth builds Entra ID token sources for each Defender tenant.
package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/jercle/datafetch/mdetracker/internal/config"
	"github.com/jercle/datafetch/mdetracker/internal/defender"
)

type tokenSource struct {
	cred  azcore.TokenCredential
	scope string
}

// Token uses the credential's built-in cache, so it is cheap to call per request.
func (t tokenSource) Token(ctx context.Context) (string, error) {
	tok, err := t.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{t.scope}})
	if err != nil {
		return "", err
	}
	return tok.Token, nil
}

// New returns a token source for the tenant. The app registration needs the
// WindowsDefenderATP application permission Machine.Read.All, admin-consented
// in that tenant.
func New(t config.Tenant, scope string) (defender.TokenSource, error) {
	cred, err := credential(t)
	if err != nil {
		return nil, fmt.Errorf("tenant %s: %w", t.Name, err)
	}
	return tokenSource{cred: cred, scope: scope}, nil
}

func credential(t config.Tenant) (azcore.TokenCredential, error) {
	a := t.Auth
	switch a.Type {
	case config.AuthSecret:
		return azidentity.NewClientSecretCredential(t.TenantID, a.ClientID, a.ClientSecret, nil)
	case config.AuthCertificate:
		data, err := os.ReadFile(a.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		var pw []byte
		if a.CertificatePassword != "" {
			pw = []byte(a.CertificatePassword)
		}
		certs, key, err := azidentity.ParseCertificates(data, pw)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return azidentity.NewClientCertificateCredential(t.TenantID, a.ClientID, certs, key, nil)
	case config.AuthWorkload:
		// Multi-tenant app with a federated credential; the token exchange targets t.TenantID.
		return azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			TenantID: t.TenantID,
			ClientID: a.ClientID, // empty = AZURE_CLIENT_ID
		})
	case config.AuthDefault:
		return azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{TenantID: t.TenantID})
	}
	return nil, fmt.Errorf("unsupported auth type %q", a.Type)
}
