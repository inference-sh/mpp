package mpp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("test-secret-key-that-is-32-bytes!")

// credFromChallenge builds a CredentialChallenge by copying fields from a Challenge.
func credFromChallenge(c *Challenge) CredentialChallenge {
	return CredentialChallenge{
		ID:      c.ID,
		Realm:   c.Realm,
		Method:  c.Method,
		Intent:  c.Intent,
		Request: c.RequestRaw,
		Expires: c.Expires,
		Digest:  c.Digest,
		Opaque:  c.OpaqueRaw,
	}
}

func TestGenerateChallengeID_Deterministic(t *testing.T) {
	id1 := generateChallengeID(testSecret, "api.example.com", "stripe", "charge", "eyJhbW91bnQ9", "", "", "")
	id2 := generateChallengeID(testSecret, "api.example.com", "stripe", "charge", "eyJhbW91bnQ9", "", "", "")
	if id1 != id2 {
		t.Fatalf("expected deterministic IDs, got %q and %q", id1, id2)
	}
}

func TestGenerateChallengeID_DifferentInputs(t *testing.T) {
	id1 := generateChallengeID(testSecret, "api.example.com", "stripe", "charge", "eyJhbW91bnQ9", "", "", "")
	id2 := generateChallengeID(testSecret, "api.example.com", "stripe", "charge", "eyJkaWZmZXI9", "", "", "")
	if id1 == id2 {
		t.Fatal("different inputs should produce different IDs")
	}
}

func TestGenerateChallengeID_DifferentSecrets(t *testing.T) {
	id1 := generateChallengeID(testSecret, "api.example.com", "stripe", "charge", "eyJhbW91bnQ9", "", "", "")
	id2 := generateChallengeID([]byte("different-secret-key-32-bytes!!!"), "api.example.com", "stripe", "charge", "eyJhbW91bnQ9", "", "", "")
	if id1 == id2 {
		t.Fatal("different secrets should produce different IDs")
	}
}

func TestVerifyChallengeID(t *testing.T) {
	challenge, err := NewChallenge(testSecret, "api.example.com", "stripe", IntentCharge, map[string]any{
		"amount":   "1000",
		"currency": "usd",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyChallengeID(testSecret, credFromChallenge(challenge)) {
		t.Fatal("valid challenge should verify")
	}
}

func TestVerifyChallengeID_Tampered(t *testing.T) {
	challenge, err := NewChallenge(testSecret, "api.example.com", "stripe", IntentCharge, map[string]any{
		"amount":   "1000",
		"currency": "usd",
	})
	if err != nil {
		t.Fatal(err)
	}

	cred := credFromChallenge(challenge)
	cred.Request = b64.EncodeToString([]byte(`{"amount":"9999","currency":"usd"}`))
	if VerifyChallengeID(testSecret, cred) {
		t.Fatal("tampered challenge should not verify")
	}
}

func TestVerifyChallengeID_WrongSecret(t *testing.T) {
	challenge, err := NewChallenge(testSecret, "api.example.com", "stripe", IntentCharge, map[string]any{
		"amount": "500",
	})
	if err != nil {
		t.Fatal(err)
	}

	if VerifyChallengeID([]byte("wrong-secret-key-that-is-32byte!"), credFromChallenge(challenge)) {
		t.Fatal("wrong secret should not verify")
	}
}

func TestNewChallenge_WithExpiry(t *testing.T) {
	expiry := time.Now().Add(5 * time.Minute)
	challenge, err := NewChallenge(testSecret, "api.example.com", "stripe", IntentCharge,
		map[string]any{"amount": "100"},
		WithExpiry(expiry),
	)
	if err != nil {
		t.Fatal(err)
	}

	if challenge.Expires == "" {
		t.Fatal("expected expires to be set")
	}

	parsed, err := time.Parse(time.RFC3339, challenge.Expires)
	if err != nil {
		t.Fatalf("invalid expires format: %v", err)
	}
	if parsed.Sub(expiry).Abs() > time.Second {
		t.Fatalf("expected expiry ~%v, got %v", expiry, parsed)
	}

	if !VerifyChallengeID(testSecret, credFromChallenge(challenge)) {
		t.Fatal("challenge with expiry should verify when expiry is echoed")
	}
}

func TestNewChallenge_WithOpaque(t *testing.T) {
	opaque := map[string]string{"app_id": "seedance", "version": "2"}
	challenge, err := NewChallenge(testSecret, "api.example.com", "stripe", IntentCharge,
		map[string]any{"amount": "100"},
		WithOpaque(opaque),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyChallengeID(testSecret, credFromChallenge(challenge)) {
		t.Fatal("challenge with opaque should verify")
	}
}

func TestFormatWWWAuthenticate(t *testing.T) {
	challenge, err := NewChallenge(testSecret, "api.example.com", "stripe", IntentCharge, map[string]any{
		"amount":   "1000",
		"currency": "usd",
	})
	if err != nil {
		t.Fatal(err)
	}

	header := challenge.FormatWWWAuthenticate()

	if !strings.HasPrefix(header, "Payment ") {
		t.Fatalf("expected Payment scheme prefix, got %q", header[:min(10, len(header))])
	}
	for _, field := range []string{"id=", "realm=", "method=", "intent=", "request="} {
		if !strings.Contains(header, field) {
			t.Fatalf("missing field %q in header: %s", field, header)
		}
	}
}

func TestFormatWWWAuthenticate_WithOptionalFields(t *testing.T) {
	expiry := time.Now().Add(5 * time.Minute)
	challenge, err := NewChallenge(testSecret, "api.example.com", "stripe", IntentCharge,
		map[string]any{"amount": "1000"},
		WithExpiry(expiry),
		WithDescription("image generation"),
	)
	if err != nil {
		t.Fatal(err)
	}

	header := challenge.FormatWWWAuthenticate()
	if !strings.Contains(header, "expires=") {
		t.Fatal("missing expires in header")
	}
	if !strings.Contains(header, "description=") {
		t.Fatal("missing description in header")
	}
}

func TestParseCredential(t *testing.T) {
	cred := &Credential{
		Challenge: CredentialChallenge{
			ID:      "test-id",
			Realm:   "api.example.com",
			Method:  "stripe",
			Intent:  "charge",
			Request: "eyJhbW91bnQiOiIxMDAifQ",
		},
		Source:  "did:pkh:eip155:1:0xabc",
		Payload: json.RawMessage(`{"spt":"spt_test123"}`),
	}

	credJSON, _ := json.Marshal(cred)
	encoded := b64.EncodeToString(credJSON)
	header := "Payment " + encoded

	parsed, err := ParseCredential(header)
	if err != nil {
		t.Fatal(err)
	}
	if parsed == nil {
		t.Fatal("expected credential, got nil")
	}
	if parsed.Challenge.ID != "test-id" {
		t.Fatalf("expected challenge ID test-id, got %q", parsed.Challenge.ID)
	}
	if parsed.Challenge.Method != "stripe" {
		t.Fatalf("expected method stripe, got %q", parsed.Challenge.Method)
	}
	if parsed.Source != "did:pkh:eip155:1:0xabc" {
		t.Fatalf("expected source, got %q", parsed.Source)
	}
}

func TestParseCredential_NotPaymentScheme(t *testing.T) {
	cred, err := ParseCredential("Bearer some-api-key")
	if err != nil {
		t.Fatal(err)
	}
	if cred != nil {
		t.Fatal("expected nil for non-Payment scheme")
	}
}

func TestParseCredential_EmptyHeader(t *testing.T) {
	cred, err := ParseCredential("")
	if err != nil {
		t.Fatal(err)
	}
	if cred != nil {
		t.Fatal("expected nil for empty header")
	}
}

func TestParseCredential_InvalidBase64(t *testing.T) {
	_, err := ParseCredential("Payment !!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseCredential_InvalidJSON(t *testing.T) {
	encoded := b64.EncodeToString([]byte("not json"))
	_, err := ParseCredential("Payment " + encoded)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestReceipt_FormatHeader(t *testing.T) {
	receipt := NewReceipt("stripe", "pi_test123")
	header := receipt.FormatHeader()

	decoded, err := b64.DecodeString(header)
	if err != nil {
		t.Fatalf("receipt header is not valid base64url: %v", err)
	}

	var parsed Receipt
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		t.Fatalf("receipt header is not valid JSON: %v", err)
	}
	if parsed.Status != ReceiptStatusSuccess {
		t.Fatalf("expected status %q, got %q", ReceiptStatusSuccess, parsed.Status)
	}
	if parsed.Method != "stripe" {
		t.Fatalf("expected method stripe, got %q", parsed.Method)
	}
	if parsed.Reference != "pi_test123" {
		t.Fatalf("expected reference pi_test123, got %q", parsed.Reference)
	}
	if parsed.Timestamp == "" {
		t.Fatal("expected timestamp")
	}
}

func TestRoundTrip_ChallengeToCredentialToVerify(t *testing.T) {
	challenge, err := NewChallenge(testSecret, "api.example.com", "stripe", IntentCharge, map[string]any{
		"amount":   "500",
		"currency": "usd",
		"decimals": 2,
	}, WithExpiry(time.Now().Add(5*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}

	_ = challenge.FormatWWWAuthenticate()

	cred := &Credential{
		Challenge: credFromChallenge(challenge),
		Source:    "did:pkh:eip155:1:0xuser",
		Payload:   json.RawMessage(`{"spt":"spt_abc"}`),
	}

	credJSON, _ := json.Marshal(cred)
	authHeader := "Payment " + b64.EncodeToString(credJSON)

	parsed, err := ParseCredential(authHeader)
	if err != nil {
		t.Fatalf("parse credential: %v", err)
	}

	if !VerifyChallengeID(testSecret, parsed.Challenge) {
		t.Fatal("round-trip challenge verification failed")
	}
}

func TestNewProblem(t *testing.T) {
	problem := NewProblem(ProblemPaymentRequired, "Payment Required", 402, "Payment is required.")
	if problem.Type != ProblemPaymentRequired {
		t.Fatalf("expected type %q, got %q", ProblemPaymentRequired, problem.Type)
	}
	if problem.Status != 402 {
		t.Fatalf("expected status 402, got %d", problem.Status)
	}
}
