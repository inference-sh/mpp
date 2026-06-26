package mpp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockMethod is a test payment method that always succeeds or fails based on config.
type mockMethod struct {
	name      string
	verifyErr error
	reference string
}

func (m *mockMethod) Name() string { return m.name }

func (m *mockMethod) ChallengeRequest(amount, currency string) map[string]any {
	return map[string]any{
		"amount":   amount,
		"currency": currency,
	}
}

func (m *mockMethod) Verify(_ context.Context, _ *Credential, _, _ string) (string, error) {
	if m.verifyErr != nil {
		return "", m.verifyErr
	}
	return m.reference, nil
}

func newTestConfig(methods ...Method) Config {
	if len(methods) == 0 {
		methods = []Method{&mockMethod{name: "test", reference: "ref_123"}}
	}
	return Config{
		SecretKey: testSecret,
		Realm:     "api.test.com",
		Methods:   methods,
		Price: func(r *http.Request) (string, string, error) {
			return "1000", "usd", nil
		},
		ChallengeExpiry: 5 * time.Minute,
	}
}

// payWithChallenge performs the 402 challenge-credential round trip:
// sends a request, extracts the challenge from WWW-Authenticate, builds a credential,
// and retries with the payment Authorization header.
func payWithChallenge(t *testing.T, handler http.Handler, payload string) *httptest.ResponseRecorder {
	t.Helper()

	// step 1: get the challenge
	req1 := httptest.NewRequest("POST", "/apps/run", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != 402 {
		t.Fatalf("step 1: expected 402, got %d", rec1.Code)
	}

	wwwAuth := rec1.Header().Get("WWW-Authenticate")
	cred := &Credential{
		Challenge: CredentialChallenge{
			ID:      extractParam(wwwAuth, "id"),
			Realm:   extractParam(wwwAuth, "realm"),
			Method:  extractParam(wwwAuth, "method"),
			Intent:  extractParam(wwwAuth, "intent"),
			Request: extractParam(wwwAuth, "request"),
			Expires: extractParam(wwwAuth, "expires"),
		},
		Source:  "did:pkh:eip155:1:0xtest",
		Payload: json.RawMessage(payload),
	}

	credJSON, _ := json.Marshal(cred)
	authHeader := "Payment " + b64.EncodeToString(credJSON)

	// step 2: retry with payment
	req2 := httptest.NewRequest("POST", "/apps/run", nil)
	req2.Header.Set("Authorization", authHeader)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	return rec2
}

func TestMiddleware_NoCreds_Returns402(t *testing.T) {
	handler := Middleware(newTestConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("POST", "/apps/run", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 402 {
		t.Fatalf("expected 402, got %d", rec.Code)
	}

	authHeader := rec.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
	if !strings.HasPrefix(authHeader, "Payment ") {
		t.Fatalf("WWW-Authenticate should start with Payment, got %q", authHeader)
	}

	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", rec.Header().Get("Cache-Control"))
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("expected application/problem+json, got %q", ct)
	}

	var problem ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Type != ProblemPaymentRequired {
		t.Fatalf("expected problem type %q, got %q", ProblemPaymentRequired, problem.Type)
	}
	if problem.Status != 402 {
		t.Fatalf("expected status 402, got %d", problem.Status)
	}
}

func TestMiddleware_MultiplePaymentMethods(t *testing.T) {
	cfg := newTestConfig(
		&mockMethod{name: "stripe", reference: "pi_123"},
		&mockMethod{name: "tempo", reference: "0xabc"},
	)
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("POST", "/apps/run", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 402 {
		t.Fatalf("expected 402, got %d", rec.Code)
	}

	headers := rec.Header().Values("WWW-Authenticate")
	if len(headers) != 2 {
		t.Fatalf("expected 2 WWW-Authenticate headers, got %d", len(headers))
	}
	if !strings.Contains(headers[0], `method="stripe"`) {
		t.Fatalf("first header should be stripe, got %q", headers[0])
	}
	if !strings.Contains(headers[1], `method="tempo"`) {
		t.Fatalf("second header should be tempo, got %q", headers[1])
	}
}

func TestMiddleware_ValidPayment_PassesThrough(t *testing.T) {
	cfg := newTestConfig(&mockMethod{name: "stripe", reference: "pi_test"})
	var handlerCalled bool

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		receipt := ReceiptFromContext(r.Context())
		if receipt == nil {
			t.Fatal("expected receipt in context")
		}
		if receipt.Reference != "pi_test" {
			t.Fatalf("expected reference pi_test, got %q", receipt.Reference)
		}
		if receipt.Method != "stripe" {
			t.Fatalf("expected method stripe, got %q", receipt.Method)
		}

		cred := CredentialFromContext(r.Context())
		if cred == nil {
			t.Fatal("expected credential in context")
		}

		w.WriteHeader(200)
		w.Write([]byte(`{"result":"ok"}`))
	}))

	rec := payWithChallenge(t, handler, `{"spt":"spt_test"}`)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d. body: %s", rec.Code, rec.Body.String())
	}
	if !handlerCalled {
		t.Fatal("handler was not called")
	}
	if rec.Header().Get("Payment-Receipt") == "" {
		t.Fatal("missing Payment-Receipt header")
	}
	if rec.Header().Get("Cache-Control") != "private" {
		t.Fatalf("expected Cache-Control: private, got %q", rec.Header().Get("Cache-Control"))
	}
}

func TestMiddleware_TamperedChallenge_Rejected(t *testing.T) {
	cfg := newTestConfig(&mockMethod{name: "stripe", reference: "pi_test"})
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for tampered challenge")
	}))

	// get challenge
	req1 := httptest.NewRequest("POST", "/apps/run", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	wwwAuth := rec1.Header().Get("WWW-Authenticate")
	challengeID := extractParam(wwwAuth, "id")

	// construct credential with tampered request (different amount)
	cred := &Credential{
		Challenge: CredentialChallenge{
			ID:      challengeID,
			Realm:   "api.test.com",
			Method:  "stripe",
			Intent:  "charge",
			Request: b64.EncodeToString([]byte(`{"amount":"999999","currency":"usd"}`)),
		},
		Payload: json.RawMessage(`{"spt":"spt_test"}`),
	}

	credJSON, _ := json.Marshal(cred)
	req2 := httptest.NewRequest("POST", "/apps/run", nil)
	req2.Header.Set("Authorization", "Payment "+b64.EncodeToString(credJSON))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != 402 {
		t.Fatalf("expected 402 for tampered challenge, got %d", rec2.Code)
	}

	var problem ProblemDetails
	json.NewDecoder(rec2.Body).Decode(&problem)
	if problem.Type != ProblemInvalidChallenge {
		t.Fatalf("expected invalid-challenge problem, got %q", problem.Type)
	}
}

func TestMiddleware_ExpiredChallenge_ReissuesChallenge(t *testing.T) {
	cfg := newTestConfig(&mockMethod{name: "stripe", reference: "pi_test"})
	cfg.ChallengeExpiry = -1 * time.Second
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for expired challenge")
	}))

	rec := payWithChallenge(t, handler, `{"spt":"spt_test"}`)

	if rec.Code != 402 {
		t.Fatalf("expected 402 for expired challenge, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected new WWW-Authenticate header on reissue")
	}
}

func TestMiddleware_VerifyFails_Returns402(t *testing.T) {
	cfg := newTestConfig(&mockMethod{
		name:      "stripe",
		verifyErr: &PaymentError{Problem: ProblemVerificationFailed, Detail: "card declined"},
	})
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called on verify failure")
	}))

	rec := payWithChallenge(t, handler, `{"spt":"spt_declined"}`)

	if rec.Code != 402 {
		t.Fatalf("expected 402, got %d", rec.Code)
	}

	var problem ProblemDetails
	json.NewDecoder(rec.Body).Decode(&problem)
	if problem.Type != ProblemVerificationFailed {
		t.Fatalf("expected verification-failed, got %q", problem.Type)
	}
}

func TestMiddleware_AllowFallthrough_BearerPassesThrough(t *testing.T) {
	cfg := newTestConfig()
	cfg.AllowFallthrough = true
	var handlerCalled bool

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("POST", "/apps/run", nil)
	req.Header.Set("Authorization", "Bearer 1nfsh-some-api-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200 for Bearer fallthrough, got %d", rec.Code)
	}
	if !handlerCalled {
		t.Fatal("handler should be called in fallthrough mode with Bearer auth")
	}
}

func TestMiddleware_AllowFallthrough_NoAuth_IssuesChallenge(t *testing.T) {
	cfg := newTestConfig()
	cfg.AllowFallthrough = true

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called without any auth")
	}))

	req := httptest.NewRequest("POST", "/apps/run", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 402 {
		t.Fatalf("expected 402, got %d", rec.Code)
	}
}

func TestMiddleware_OnPayment_Called(t *testing.T) {
	var paymentRecorded bool
	var recordedAmount string
	var recordedCurrency string

	cfg := newTestConfig(&mockMethod{name: "stripe", reference: "pi_recorded"})
	cfg.OnPayment = func(ctx context.Context, receipt *Receipt, cred *Credential, amount, currency string) error {
		paymentRecorded = true
		recordedAmount = amount
		recordedCurrency = currency
		return nil
	}

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := payWithChallenge(t, handler, `{"spt":"spt_test"}`)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !paymentRecorded {
		t.Fatal("OnPayment was not called")
	}
	if recordedAmount != "1000" {
		t.Fatalf("expected amount 1000, got %s", recordedAmount)
	}
	if recordedCurrency != "usd" {
		t.Fatalf("expected currency usd, got %q", recordedCurrency)
	}
}

func TestMiddleware_OnPayment_Error_Returns500(t *testing.T) {
	cfg := newTestConfig(&mockMethod{name: "stripe", reference: "pi_ok"})
	cfg.OnPayment = func(ctx context.Context, receipt *Receipt, cred *Credential, amount, currency string) error {
		return fmt.Errorf("billing system down")
	}

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called when OnPayment fails")
	}))

	rec := payWithChallenge(t, handler, `{"spt":"spt_test"}`)

	if rec.Code != 500 {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestMiddleware_UnknownMethod_Returns400(t *testing.T) {
	cfg := newTestConfig(&mockMethod{name: "stripe", reference: "pi_test"})
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	// create a valid HMAC for "tempo" method (which isn't in cfg.Methods)
	challenge, _ := NewChallenge(testSecret, "api.test.com", "tempo", IntentCharge,
		map[string]any{"amount": "1000", "currency": "usd"},
		WithExpiry(time.Now().Add(5*time.Minute)))

	cred := &Credential{
		Challenge: credFromChallenge(challenge),
		Payload:   json.RawMessage(`{}`),
	}

	credJSON, _ := json.Marshal(cred)
	req := httptest.NewRequest("POST", "/apps/run", nil)
	req.Header.Set("Authorization", "Payment "+b64.EncodeToString(credJSON))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400 for unsupported method, got %d", rec.Code)
	}
}

func TestMiddleware_MalformedCredential_Returns402(t *testing.T) {
	cfg := newTestConfig()
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("POST", "/apps/run", nil)
	req.Header.Set("Authorization", "Payment !!!invalid-base64!!!")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 402 {
		t.Fatalf("expected 402, got %d", rec.Code)
	}

	var problem ProblemDetails
	json.NewDecoder(rec.Body).Decode(&problem)
	if problem.Type != ProblemMalformedCredential {
		t.Fatalf("expected malformed-credential, got %q", problem.Type)
	}
}

func TestContextHelpers_NilWhenNotSet(t *testing.T) {
	ctx := context.Background()
	if ReceiptFromContext(ctx) != nil {
		t.Fatal("expected nil receipt from empty context")
	}
	if CredentialFromContext(ctx) != nil {
		t.Fatal("expected nil credential from empty context")
	}
}

// extractParam extracts a quoted parameter value from a WWW-Authenticate header.
func extractParam(header, name string) string {
	key := name + `="`
	idx := strings.Index(header, key)
	if idx == -1 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(header[start:], `"`)
	if end == -1 {
		return ""
	}
	return header[start : start+end]
}
