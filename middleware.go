package mpp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type contextKey string

const (
	receiptCtxKey contextKey = "mpp.receipt"
	credCtxKey    contextKey = "mpp.credential"
)

// PriceFn returns the price and currency for a given request.
// Amount is a string in the smallest currency unit (e.g. "100" for $1.00 USD,
// "1000000" for 1 USDC with 6 decimals). This is called before the handler
// to determine the payment amount.
type PriceFn func(r *http.Request) (amount, currency string, err error)

// Config configures the MPP middleware.
type Config struct {
	// SecretKey is used to HMAC-sign challenge IDs. Must be 32+ bytes, kept secret.
	SecretKey []byte

	// Realm identifies this server (typically the API hostname).
	Realm string

	// Methods lists the accepted payment methods in preference order.
	Methods []Method

	// Price returns the cost for a given request.
	Price PriceFn

	// ChallengeExpiry sets how long a challenge is valid. Defaults to 5 minutes.
	ChallengeExpiry time.Duration

	// OnPayment is called after successful payment verification, before the handler.
	// Use this to record the payment in your billing system.
	// The receipt and credential are also available via ReceiptFromContext / CredentialFromContext.
	OnPayment func(ctx context.Context, receipt *Receipt, cred *Credential, amount, currency string) error

	// AllowFallthrough, when true, calls the next handler even without payment
	// if no Authorization: Payment header is present. This lets you handle
	// both authenticated (API key) and MPP payment flows on the same route.
	AllowFallthrough bool
}

// Middleware returns an http.Handler middleware that implements the MPP payment flow.
//
// Without payment credential: returns 402 with WWW-Authenticate challenge headers.
// With valid credential: verifies payment, attaches receipt to context, calls next handler.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.ChallengeExpiry == 0 {
		cfg.ChallengeExpiry = 5 * time.Minute
	}

	// pre-compute method lookup for O(1) dispatch
	methodMap := make(map[string]Method, len(cfg.Methods))
	for _, m := range cfg.Methods {
		methodMap[m.Name()] = m
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")

			cred, err := ParseCredential(authHeader)
			if err != nil {
				writeProblem(w, http.StatusPaymentRequired, ProblemMalformedCredential, "malformed payment credential", "")
				return
			}

			if cred == nil {
				// non-Payment auth header (e.g. Bearer API key) — let it through in fallthrough mode
				if cfg.AllowFallthrough && authHeader != "" {
					next.ServeHTTP(w, r)
					return
				}

				writeChallenge(w, r, &cfg)
				return
			}

			// verify the HMAC-signed challenge ID
			if !VerifyChallengeID(cfg.SecretKey, cred.Challenge) {
				writeProblem(w, http.StatusPaymentRequired, ProblemInvalidChallenge, "invalid or tampered challenge", "")
				return
			}

			// check expiry
			if cred.Challenge.Expires != "" {
				expiry, err := time.Parse(time.RFC3339, cred.Challenge.Expires)
				if err != nil || time.Now().UTC().After(expiry) {
					writeChallenge(w, r, &cfg)
					return
				}
			}

			// find the matching payment method
			method, ok := methodMap[cred.Challenge.Method]
			if !ok {
				writeProblem(w, http.StatusBadRequest, ProblemMethodUnsupported, "unsupported payment method: "+cred.Challenge.Method, "")
				return
			}

			// get the expected price
			amount, currency, err := cfg.Price(r)
			if err != nil {
				writeProblem(w, http.StatusInternalServerError, ProblemVerificationFailed, "failed to determine price", "")
				return
			}

			// verify payment with the method provider
			reference, err := method.Verify(r.Context(), cred, amount, currency)
			if err != nil {
				var pe *PaymentError
				if errors.As(err, &pe) {
					writeProblem(w, http.StatusPaymentRequired, pe.Problem, pe.Detail, "")
				} else {
					writeProblem(w, http.StatusPaymentRequired, ProblemVerificationFailed, err.Error(), "")
				}
				return
			}

			receipt := NewReceipt(method.Name(), reference)

			// notify the billing system
			if cfg.OnPayment != nil {
				if err := cfg.OnPayment(r.Context(), receipt, cred, amount, currency); err != nil {
					writeProblem(w, http.StatusInternalServerError, "https://paymentauth.org/problems/internal-error", "internal error", "")
					return
				}
			}

			// attach receipt and credential to context
			ctx := context.WithValue(r.Context(), receiptCtxKey, receipt)
			ctx = context.WithValue(ctx, credCtxKey, cred)

			// set receipt header
			w.Header().Set("Payment-Receipt", receipt.FormatHeader())
			w.Header().Set("Cache-Control", "private")

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ReceiptFromContext returns the payment receipt from the request context, if present.
func ReceiptFromContext(ctx context.Context) *Receipt {
	if v := ctx.Value(receiptCtxKey); v != nil {
		return v.(*Receipt)
	}
	return nil
}

// CredentialFromContext returns the payment credential from the request context, if present.
func CredentialFromContext(ctx context.Context) *Credential {
	if v := ctx.Value(credCtxKey); v != nil {
		return v.(*Credential)
	}
	return nil
}

func writeChallenge(w http.ResponseWriter, r *http.Request, cfg *Config) {
	amount, currency, err := cfg.Price(r)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, ProblemVerificationFailed, "failed to determine price", "")
		return
	}

	expiry := time.Now().UTC().Add(cfg.ChallengeExpiry)

	for _, method := range cfg.Methods {
		req := method.ChallengeRequest(amount, currency)
		challenge, err := NewChallenge(
			cfg.SecretKey,
			cfg.Realm,
			method.Name(),
			IntentCharge,
			req,
			WithExpiry(expiry),
		)
		if err != nil {
			continue
		}
		w.Header().Add("WWW-Authenticate", challenge.FormatWWWAuthenticate())
	}

	w.Header().Set("Cache-Control", "no-store")
	writeProblem(w, http.StatusPaymentRequired, ProblemPaymentRequired, "Payment is required.", "")
}

func writeProblem(w http.ResponseWriter, status int, problemType, detail, challengeID string) {
	problem := ProblemDetails{
		Type:        problemType,
		Title:       http.StatusText(status),
		Status:      status,
		Detail:      detail,
		ChallengeID: challengeID,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	b, _ := json.Marshal(problem)
	_, _ = w.Write(b)
}
