package mpp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v84"
)

// issueChallenge fetches a challenge from handler.
func issueChallenge(t *testing.T, handler http.Handler) CredentialChallenge {
	t.Helper()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/apps/run", nil))
	if rec.Code != 402 {
		t.Fatalf("expected 402 challenge, got %d", rec.Code)
	}

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	return CredentialChallenge{
		ID:      extractParam(wwwAuth, "id"),
		Realm:   extractParam(wwwAuth, "realm"),
		Method:  extractParam(wwwAuth, "method"),
		Intent:  extractParam(wwwAuth, "intent"),
		Request: extractParam(wwwAuth, "request"),
		Expires: extractParam(wwwAuth, "expires"),
	}
}

// credentialFor returns the Authorization header value for a credential
// answering challenge with the given payload.
func credentialFor(challenge CredentialChallenge, payload string) string {
	credJSON, _ := json.Marshal(&Credential{Challenge: challenge, Payload: json.RawMessage(payload)})
	return "Payment " + b64.EncodeToString(credJSON)
}

// issueCredential fetches a challenge from handler and answers it with payload.
func issueCredential(t *testing.T, handler http.Handler, payload string) string {
	t.Helper()
	return credentialFor(issueChallenge(t, handler), payload)
}

// pay sends one request carrying the given Authorization header.
func pay(handler http.Handler, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/apps/run", nil)
	req.Header.Set("Authorization", auth)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// countingHandler counts how many requests reached the paid handler.
func countingHandler(served *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.WriteHeader(200)
	})
}

// stripeStub implements Stripe's documented idempotency behaviour for
// PaymentIntent creation: the first request for a key charges, and later
// requests with that key return the saved response with Idempotent-Replayed: true.
type stripeStub struct {
	*httptest.Server

	mu       sync.Mutex
	seen     map[string]bool
	charges  int
	requests int

	// dropFirstResponse makes the stub charge on the first request and then
	// close the connection without responding.
	dropFirstResponse bool
}

func newStripeStub(t *testing.T) *stripeStub {
	t.Helper()
	s := &stripeStub{seen: map[string]bool{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests++
		first := s.requests == 1
		key := r.Header.Get("Idempotency-Key")
		replayed := s.seen[key]
		if !replayed {
			s.seen[key] = true
			s.charges++
		}
		drop := s.dropFirstResponse && first
		s.mu.Unlock()

		if drop {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		if replayed {
			w.Header().Set("Idempotent-Replayed", "true")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"pi_stub","object":"payment_intent","status":"succeeded","metadata":{"mpp_version":"1"}}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *stripeStub) counts() (charges, requests int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.charges, s.requests
}

func (s *stripeStub) method() *StripeMethod {
	backends := stripe.NewBackendsWithConfig(&stripe.BackendConfig{URL: stripe.String(s.URL)})
	if impl, ok := backends.API.(*stripe.BackendImplementation); ok {
		impl.SetNetworkRetriesSleep(false)
	}
	return &StripeMethod{
		Client:             stripe.NewClient("sk_test_stub", stripe.WithBackends(backends)),
		NetworkID:          "profile_test",
		PaymentMethodTypes: []string{"card"},
	}
}

func TestStripe_ReplayedCredentialServedOnce(t *testing.T) {
	stub := newStripeStub(t)
	var served atomic.Int32
	handler := Middleware(newTestConfig(stub.method()))(countingHandler(&served))

	auth := issueCredential(t, handler, `{"spt":"spt_abc"}`)

	if rec := pay(handler, auth); rec.Code != 200 {
		t.Fatalf("first payment: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	for i := 2; i <= 5; i++ {
		rec := pay(handler, auth)
		if rec.Code != 402 {
			t.Fatalf("replay %d: expected 402, got %d", i, rec.Code)
		}
		if rec.Header().Get("Payment-Receipt") != "" {
			t.Fatalf("replay %d: must not carry a receipt", i)
		}
	}

	charges, requests := stub.counts()
	if served.Load() != 1 || charges != 1 {
		t.Fatalf("expected 1 served for 1 charge, got %d served for %d charges", served.Load(), charges)
	}
	if requests != 1 {
		t.Fatalf("replays must be rejected before reaching Stripe, got %d Stripe requests", requests)
	}
}

func TestStripe_ReplayWithReshapedPayloadRejected(t *testing.T) {
	stub := newStripeStub(t)
	var served atomic.Int32
	cfg := newTestConfig(stub.method())
	handler := Middleware(cfg)(countingHandler(&served))

	// same challenge and same SPT, different payload bytes
	challenge := issueChallenge(t, handler)
	auth := credentialFor(challenge, `{"spt":"spt_abc"}`)
	reshaped := credentialFor(challenge, `{"externalId":"x", "spt":"spt_abc"}`)

	if rec := pay(handler, auth); rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec := pay(handler, reshaped); rec.Code != 402 {
		t.Fatalf("reshaped replay: expected 402, got %d", rec.Code)
	}
	if served.Load() != 1 {
		t.Fatalf("expected 1 served, got %d", served.Load())
	}
}

func TestStripe_DistinctPaymentsOnSameChallengeBothServed(t *testing.T) {
	stub := newStripeStub(t)
	var served atomic.Int32
	handler := Middleware(newTestConfig(stub.method()))(countingHandler(&served))

	// challenge IDs are deterministic within a second, so two clients can hold
	// the same challenge. each pays with their own SPT.
	challenge := issueChallenge(t, handler)
	a := credentialFor(challenge, `{"spt":"spt_client_a"}`)
	b := credentialFor(challenge, `{"spt":"spt_client_b"}`)

	if rec := pay(handler, a); rec.Code != 200 {
		t.Fatalf("client a: expected 200, got %d", rec.Code)
	}
	if rec := pay(handler, b); rec.Code != 200 {
		t.Fatalf("client b: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	charges, _ := stub.counts()
	if served.Load() != 2 || charges != 2 {
		t.Fatalf("expected 2 served for 2 charges, got %d served for %d charges", served.Load(), charges)
	}
}

func TestStripe_SDKRetryAfterLostResponseStillServed(t *testing.T) {
	stub := newStripeStub(t)
	stub.dropFirstResponse = true
	var served atomic.Int32
	handler := Middleware(newTestConfig(stub.method()))(countingHandler(&served))

	auth := issueCredential(t, handler, `{"spt":"spt_abc"}`)

	// Stripe charges, the response is lost, stripe-go retries and receives the
	// saved result flagged Idempotent-Replayed. the payer must still be served.
	if rec := pay(handler, auth); rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := pay(handler, auth); rec.Code != 402 {
		t.Fatalf("replay: expected 402, got %d", rec.Code)
	}

	charges, requests := stub.counts()
	if served.Load() != 1 || charges != 1 {
		t.Fatalf("expected 1 served for 1 charge, got %d served for %d charges", served.Load(), charges)
	}
	if requests != 2 {
		t.Fatalf("expected the SDK to retry once (2 Stripe requests), got %d", requests)
	}
}

func TestStripe_RetryAfterOnPaymentFailureServedOnce(t *testing.T) {
	stub := newStripeStub(t)
	var served atomic.Int32
	var failBilling atomic.Bool
	failBilling.Store(true)

	cfg := newTestConfig(stub.method())
	cfg.OnPayment = func(context.Context, *Receipt, *Credential, string, string) error {
		if failBilling.Load() {
			return errors.New("billing system down")
		}
		return nil
	}
	handler := Middleware(cfg)(countingHandler(&served))

	auth := issueCredential(t, handler, `{"spt":"spt_abc"}`)

	// charged, but not served
	if rec := pay(handler, auth); rec.Code != 500 {
		t.Fatalf("expected 500, got %d", rec.Code)
	}

	// the same credential can be retried and is served without a second charge
	failBilling.Store(false)
	if rec := pay(handler, auth); rec.Code != 200 {
		t.Fatalf("retry: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := pay(handler, auth); rec.Code != 402 {
		t.Fatalf("replay: expected 402, got %d", rec.Code)
	}

	charges, _ := stub.counts()
	if served.Load() != 1 || charges != 1 {
		t.Fatalf("expected 1 served for 1 charge, got %d served for %d charges", served.Load(), charges)
	}
}

func TestStripe_DirectVerifyRejectsReplay(t *testing.T) {
	stub := newStripeStub(t)
	method := stub.method()

	challenge, err := NewChallenge(testSecret, "api.test.com", "stripe", IntentCharge,
		method.ChallengeRequest("1000", "usd"), WithExpiry(time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	cred := &Credential{
		Challenge: CredentialChallenge{ID: challenge.ID, Request: challenge.RequestRaw},
		Payload:   json.RawMessage(`{"spt":"spt_abc"}`),
	}

	// no middleware, so no Store claim protects this credential
	if _, err := method.Verify(context.Background(), cred, "1000", "usd"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err = method.Verify(context.Background(), cred, "1000", "usd")
	var pe *PaymentError
	if !errors.As(err, &pe) || pe.Problem != ProblemVerificationFailed {
		t.Fatalf("replayed verify: expected verification-failed, got %v", err)
	}
}

func TestMiddleware_ReplayRejectedForMethodWithoutReplayKey(t *testing.T) {
	var served atomic.Int32
	handler := Middleware(newTestConfig())(countingHandler(&served))

	auth := issueCredential(t, handler, `{"token":"t"}`)

	if rec := pay(handler, auth); rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	rec := pay(handler, auth)
	if rec.Code != 402 {
		t.Fatalf("replay: expected 402, got %d", rec.Code)
	}
	var problem ProblemDetails
	_ = json.Unmarshal(rec.Body.Bytes(), &problem)
	if problem.Type != ProblemInvalidChallenge {
		t.Fatalf("expected invalid-challenge problem, got %q", problem.Type)
	}
	if served.Load() != 1 {
		t.Fatalf("expected 1 served, got %d", served.Load())
	}
}

func TestMiddleware_ConcurrentReplayServedOnce(t *testing.T) {
	var served atomic.Int32
	handler := Middleware(newTestConfig())(countingHandler(&served))

	auth := issueCredential(t, handler, `{"token":"t"}`)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pay(handler, auth)
		}()
	}
	wg.Wait()

	if served.Load() != 1 {
		t.Fatalf("expected exactly 1 served request, got %d", served.Load())
	}
}

func TestMiddleware_SharedStoreBlocksReplayAcrossInstances(t *testing.T) {
	store := NewMemoryStore()
	var served atomic.Int32

	cfgA := newTestConfig()
	cfgA.Store = store
	cfgB := newTestConfig()
	cfgB.Store = store
	instanceA := Middleware(cfgA)(countingHandler(&served))
	instanceB := Middleware(cfgB)(countingHandler(&served))

	auth := issueCredential(t, instanceA, `{"token":"t"}`)

	if rec := pay(instanceA, auth); rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec := pay(instanceB, auth); rec.Code != 402 {
		t.Fatalf("replay on second instance: expected 402, got %d", rec.Code)
	}
	if served.Load() != 1 {
		t.Fatalf("expected 1 served, got %d", served.Load())
	}
}

// flakyMethod fails verification until told to succeed.
type flakyMethod struct {
	mockMethod
	fail atomic.Bool
}

func (m *flakyMethod) Verify(context.Context, *Credential, string, string) (string, error) {
	if m.fail.Load() {
		return "", errors.New("provider unavailable")
	}
	return m.reference, nil
}

func TestMiddleware_FailedVerifyReleasesClaim(t *testing.T) {
	method := &flakyMethod{mockMethod: mockMethod{name: "test", reference: "ref_1"}}
	method.fail.Store(true)
	var served atomic.Int32
	handler := Middleware(newTestConfig(method))(countingHandler(&served))

	auth := issueCredential(t, handler, `{"token":"t"}`)

	if rec := pay(handler, auth); rec.Code != 402 {
		t.Fatalf("failed verify: expected 402, got %d", rec.Code)
	}

	method.fail.Store(false)
	if rec := pay(handler, auth); rec.Code != 200 {
		t.Fatalf("retry after failed verify: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := pay(handler, auth); rec.Code != 402 {
		t.Fatalf("replay: expected 402, got %d", rec.Code)
	}
	if served.Load() != 1 {
		t.Fatalf("expected 1 served, got %d", served.Load())
	}
}

// brokenStore fails every operation.
type brokenStore struct{}

func (brokenStore) Claim(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("store unavailable")
}
func (brokenStore) Release(context.Context, string) error { return nil }

// spyMethod records whether Verify was called.
type spyMethod struct {
	mockMethod
	verified atomic.Bool
}

func (m *spyMethod) Verify(context.Context, *Credential, string, string) (string, error) {
	m.verified.Store(true)
	return m.reference, nil
}

func TestMiddleware_StoreErrorFailsClosed(t *testing.T) {
	method := &spyMethod{mockMethod: mockMethod{name: "test", reference: "ref_1"}}
	issuer := Middleware(newTestConfig(method))(http.NotFoundHandler())
	auth := issueCredential(t, issuer, `{"token":"t"}`)

	cfg := newTestConfig(method)
	cfg.Store = brokenStore{}
	var served atomic.Int32
	handler := Middleware(cfg)(countingHandler(&served))

	if rec := pay(handler, auth); rec.Code != 500 {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if method.verified.Load() {
		t.Fatal("payment must not be settled when the credential cannot be claimed")
	}
	if served.Load() != 0 {
		t.Fatal("handler must not be served when the store is unavailable")
	}
}
