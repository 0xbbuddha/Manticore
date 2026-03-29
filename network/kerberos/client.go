package kerberos

import (
	"fmt"
	"strings"

	gocreds "github.com/jcmturner/gokrb5/v8/credentials"
	krb5client "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// KerberosClient manages Kerberos authentication against an Active Directory KDC.
// It wraps gokrb5 to provide protocol-level primitives: TGT acquisition, TGS
// requests, and ccache loading.
//
// Typical usage:
//
//	c := kerberos.NewClient("john", "CORP.LOCAL", "10.0.0.1")
//	c.WithPassword("secret")
//	if err := c.GetTGT(); err != nil { ... }
//	ticket, key, err := c.GetTGS("cifs/dc01.corp.local")
type KerberosClient struct {
	username string
	realm    string
	kdcHost  string
	inner    *krb5client.Client
}

// NewClient creates a new KerberosClient for the given username, realm, and KDC host.
// The realm is automatically uppercased (required by the Kerberos specification).
// Call WithPassword or WithCCache before calling GetTGT.
func NewClient(username, realm, kdcHost string) *KerberosClient {
	return &KerberosClient{
		username: username,
		realm:    strings.ToUpper(realm),
		kdcHost:  kdcHost,
	}
}

// WithPassword configures the client to authenticate with a plaintext password.
// Returns the client to allow fluent chaining.
func (c *KerberosClient) WithPassword(password string) *KerberosClient {
	_, cfg := KerberosInit(c.kdcHost, c.realm)
	c.inner = krb5client.NewWithPassword(
		c.username,
		c.realm,
		password,
		cfg,
		// Active Directory does not commonly support FAST negotiation.
		// Without this setting, authentication fails with:
		// "KDC did not respond appropriately to FAST negotiation"
		krb5client.DisablePAFXFAST(true),
	)
	return c
}

// WithCCache loads tickets from a ccache file and initialises the inner client.
// This enables Pass-the-Ticket workflows: load an existing TGT and request TGS
// tickets without re-authenticating.
func (c *KerberosClient) WithCCache(path string) error {
	_, cfg := KerberosInit(c.kdcHost, c.realm)
	ccache, err := gocreds.LoadCCache(path)
	if err != nil {
		return fmt.Errorf("failed to load ccache %q: %w", path, err)
	}
	inner, err := krb5client.NewFromCCache(ccache, cfg, krb5client.DisablePAFXFAST(true))
	if err != nil {
		return fmt.Errorf("failed to create client from ccache: %w", err)
	}
	c.inner = inner
	return nil
}

// GetTGT requests a Ticket Granting Ticket from the KDC using the configured
// credentials (password or ccache). Must be called before GetTGS.
func (c *KerberosClient) GetTGT() error {
	if c.inner == nil {
		return fmt.Errorf("no credentials configured: call WithPassword or WithCCache first")
	}
	return c.inner.Login()
}

// GetTGS requests a service ticket for the given Service Principal Name.
// GetTGT must have been called successfully beforehand.
//
// The returned Ticket and EncryptionKey can be used by the caller to:
//   - Format a Kerberoast hash for offline cracking
//   - Build an AP-REQ for protocol authentication
func (c *KerberosClient) GetTGS(spn string) (messages.Ticket, types.EncryptionKey, error) {
	if c.inner == nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("no credentials configured")
	}
	ticket, key, err := c.inner.GetServiceTicket(spn)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("failed to get TGS for %q: %w", spn, err)
	}
	return ticket, key, nil
}

// Destroy cleans up the Kerberos client and releases resources.
// Should be called with defer after creating the client.
func (c *KerberosClient) Destroy() {
	if c.inner != nil {
		c.inner.Destroy()
	}
}

// Username returns the username configured for this client.
func (c *KerberosClient) Username() string { return c.username }

// Realm returns the realm (uppercased) configured for this client.
func (c *KerberosClient) Realm() string { return c.realm }

// KDCHost returns the KDC host configured for this client.
func (c *KerberosClient) KDCHost() string { return c.kdcHost }
