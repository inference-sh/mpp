// Package mpp implements the Machine Payments Protocol (MPP) for Go HTTP servers.
//
// MPP enables machine-to-machine payments through HTTP 402 challenge-credential-receipt
// exchanges. When a client requests a paid resource, the server returns a 402 with payment
// details; the client authorizes payment, retries with proof, and gains access.
//
// Spec: draft-ryan-httpauth-payment-01 (IETF)
// Reference: https://mpp.dev
package mpp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Challenge represents a server-issued payment challenge returned in a 402 response.
type Challenge struct {
	ID          string `json:"id"`
	Realm       string `json:"realm"`
	Method      string `json:"method"`
	Intent      string `json:"intent"`
	RequestRaw  string `json:"-"` // base64url-encoded JCS JSON
	Expires     string `json:"expires,omitempty"`
	Digest      string `json:"digest,omitempty"`
	Description string `json:"description,omitempty"`
	OpaqueRaw   string `json:"-"` // base64url-encoded opaque, empty if none
}

// Credential represents a client-submitted payment credential in the Authorization header.
type Credential struct {
	Challenge CredentialChallenge `json:"challenge"`
	Source    string              `json:"source,omitempty"`
	Payload   json.RawMessage    `json:"payload"`
}

// CredentialChallenge is the echoed challenge inside a credential.
// Per spec, both Request and Opaque are base64url strings preserving exact bytes for HMAC.
type CredentialChallenge struct {
	ID          string `json:"id"`
	Realm       string `json:"realm"`
	Method      string `json:"method"`
	Intent      string `json:"intent"`
	Request     string `json:"request"`
	Expires     string `json:"expires,omitempty"`
	Digest      string `json:"digest,omitempty"`
	Description string `json:"description,omitempty"`
	Opaque      string `json:"opaque,omitempty"` // base64url string, NOT decoded map
}

// Receipt represents a payment receipt attached to successful responses.
type Receipt struct {
	Status     string `json:"status"`
	Method     string `json:"method"`
	Timestamp  string `json:"timestamp"`
	Reference  string `json:"reference"`
	ExternalID string `json:"externalId,omitempty"`
}

// ProblemDetails represents an RFC 9457 problem details response body.
type ProblemDetails struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Status      int    `json:"status"`
	Detail      string `json:"detail"`
	ChallengeID string `json:"challengeId,omitempty"`
}

const (
	problemBaseURI = "https://paymentauth.org/problems/"

	ProblemPaymentRequired     = problemBaseURI + "payment-required"
	ProblemPaymentInsufficient = problemBaseURI + "payment-insufficient"
	ProblemPaymentExpired      = problemBaseURI + "payment-expired"
	ProblemVerificationFailed  = problemBaseURI + "verification-failed"
	ProblemMethodUnsupported   = problemBaseURI + "method-unsupported"
	ProblemMalformedCredential = problemBaseURI + "malformed-credential"
	ProblemInvalidChallenge    = problemBaseURI + "invalid-challenge"
	ProblemInvalidPayload      = problemBaseURI + "invalid-payload"
	ProblemActionRequired      = problemBaseURI + "payment-action-required"

	ReceiptStatusSuccess = "success"

	IntentCharge = "charge"

	authScheme = "Payment"
)

// b64 is the base64url encoding without padding per RFC 4648 Section 5.
var b64 = base64.RawURLEncoding

// pipe is a pre-allocated separator for HMAC input.
var pipe = []byte("|")

// generateChallengeID computes an HMAC-SHA256 challenge ID from the challenge fields.
// The ID binds all challenge parameters to the server secret, preventing tampering.
func generateChallengeID(secretKey []byte, realm, method, intent, requestB64, expires, digest, opaqueB64 string) string {
	mac := hmac.New(sha256.New, secretKey)
	fields := [7]string{realm, method, intent, requestB64, expires, digest, opaqueB64}
	for i, f := range fields {
		if i > 0 {
			mac.Write(pipe)
		}
		mac.Write([]byte(f))
	}
	return b64.EncodeToString(mac.Sum(nil))
}

// VerifyChallengeID recomputes the HMAC and performs a constant-time comparison.
func VerifyChallengeID(secretKey []byte, cred CredentialChallenge) bool {
	expected := generateChallengeID(secretKey, cred.Realm, cred.Method, cred.Intent, cred.Request, cred.Expires, cred.Digest, cred.Opaque)
	return hmac.Equal([]byte(expected), []byte(cred.ID))
}

// NewChallenge creates a signed challenge for a given payment method and amount.
func NewChallenge(secretKey []byte, realm, method, intent string, request map[string]any, opts ...ChallengeOption) (*Challenge, error) {
	c := &Challenge{
		Realm:  realm,
		Method: method,
		Intent: intent,
	}
	for _, opt := range opts {
		opt(c)
	}

	reqJSON, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("mpp: marshal request: %w", err)
	}
	c.RequestRaw = b64.EncodeToString(reqJSON)

	c.ID = generateChallengeID(secretKey, c.Realm, c.Method, c.Intent, c.RequestRaw, c.Expires, c.Digest, c.OpaqueRaw)
	return c, nil
}

// ChallengeOption configures optional challenge fields.
type ChallengeOption func(*Challenge)

// WithExpiry sets the challenge expiration.
func WithExpiry(t time.Time) ChallengeOption {
	return func(c *Challenge) {
		c.Expires = t.UTC().Format(time.RFC3339)
	}
}

// WithDescription sets a human-readable description.
func WithDescription(desc string) ChallengeOption {
	return func(c *Challenge) {
		c.Description = desc
	}
}

// WithDigest sets the request body digest for body-binding.
func WithDigest(digest string) ChallengeOption {
	return func(c *Challenge) {
		c.Digest = digest
	}
}

// WithOpaque sets opaque key-value pairs echoed by the client.
// The map is serialized to a deterministic JSON string and base64url-encoded once at
// challenge creation time. Both server and client use this exact encoded form for HMAC,
// avoiding non-deterministic map key ordering issues.
func WithOpaque(kv map[string]string) ChallengeOption {
	return func(c *Challenge) {
		ob, _ := json.Marshal(kv)
		c.OpaqueRaw = b64.EncodeToString(ob)
	}
}

// FormatWWWAuthenticate formats a challenge as a WWW-Authenticate header value.
func (c *Challenge) FormatWWWAuthenticate() string {
	var b strings.Builder
	b.WriteString(authScheme)
	b.WriteString(` id="`)
	b.WriteString(c.ID)
	b.WriteString(`", realm="`)
	b.WriteString(c.Realm)
	b.WriteString(`", method="`)
	b.WriteString(c.Method)
	b.WriteString(`", intent="`)
	b.WriteString(c.Intent)
	b.WriteString(`", request="`)
	b.WriteString(c.RequestRaw)
	b.WriteString(`"`)

	if c.Expires != "" {
		b.WriteString(`, expires="`)
		b.WriteString(c.Expires)
		b.WriteString(`"`)
	}
	if c.Digest != "" {
		b.WriteString(`, digest="`)
		b.WriteString(c.Digest)
		b.WriteString(`"`)
	}
	if c.Description != "" {
		b.WriteString(`, description="`)
		b.WriteString(c.Description)
		b.WriteString(`"`)
	}
	if c.OpaqueRaw != "" {
		b.WriteString(`, opaque="`)
		b.WriteString(c.OpaqueRaw)
		b.WriteString(`"`)
	}
	return b.String()
}

// ParseCredential extracts and decodes a payment credential from an Authorization header value.
// Returns nil if the header does not use the Payment scheme.
func ParseCredential(authHeader string) (*Credential, error) {
	if !strings.HasPrefix(authHeader, authScheme+" ") {
		return nil, nil
	}
	encoded := strings.TrimPrefix(authHeader, authScheme+" ")
	decoded, err := b64.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("mpp: decode credential: %w", err)
	}
	var cred Credential
	if err := json.Unmarshal(decoded, &cred); err != nil {
		return nil, fmt.Errorf("mpp: unmarshal credential: %w", err)
	}
	return &cred, nil
}

// FormatHeader encodes a receipt as a Payment-Receipt header value.
func (r *Receipt) FormatHeader() string {
	b, _ := json.Marshal(r)
	return b64.EncodeToString(b)
}

// NewReceipt creates a receipt for a successful payment.
func NewReceipt(method, reference string) *Receipt {
	return &Receipt{
		Status:    ReceiptStatusSuccess,
		Method:    method,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Reference: reference,
	}
}

// NewProblem creates a problem details response for payment errors.
func NewProblem(problemType, title string, status int, detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:   problemType,
		Title:  title,
		Status: status,
		Detail: detail,
	}
}
