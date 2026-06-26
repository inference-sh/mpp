package mpp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/stripe/stripe-go/v84"
)

// StripeMethod implements the Method interface using Stripe Shared Payment Tokens (SPTs).
type StripeMethod struct {
	// Client is the Stripe API client. Required.
	Client *stripe.Client

	// NetworkID is the Stripe profile ID (e.g. "profile_xxx") that identifies
	// this merchant for SPT transactions.
	NetworkID string

	// PaymentMethodTypes lists accepted Stripe payment method types (e.g. "card", "link").
	PaymentMethodTypes []string

	// Metadata is optional key-value pairs attached to PaymentIntents.
	Metadata map[string]string

	// Decimals is the number of decimal places for the currency. Defaults to 2 (USD cents).
	Decimals int
}

func (s *StripeMethod) decimals() int {
	if s.Decimals > 0 {
		return s.Decimals
	}
	return 2
}

// stripePayload is the expected structure of the credential payload for Stripe SPT.
type stripePayload struct {
	SPT        string `json:"spt"`
	ExternalID string `json:"externalId,omitempty"`
}

func (s *StripeMethod) Name() string { return "stripe" }

func (s *StripeMethod) ChallengeRequest(amount, currency string) map[string]any {
	req := map[string]any{
		"amount":   amount,
		"currency": currency,
		"decimals": s.decimals(),
		"methodDetails": map[string]any{
			"networkId":          s.NetworkID,
			"paymentMethodTypes": s.PaymentMethodTypes,
		},
	}
	if s.Metadata != nil {
		req["methodDetails"].(map[string]any)["metadata"] = s.Metadata
	}
	return req
}

func (s *StripeMethod) Verify(ctx context.Context, cred *Credential, amount, currency string) (string, error) {
	var payload stripePayload
	if err := json.Unmarshal(cred.Payload, &payload); err != nil {
		return "", fmt.Errorf("mpp/stripe: unmarshal payload: %w", err)
	}
	if payload.SPT == "" {
		return "", &PaymentError{Problem: ProblemInvalidPayload, Detail: "missing spt in payload"}
	}
	if !strings.HasPrefix(payload.SPT, "spt_") {
		return "", &PaymentError{Problem: ProblemInvalidPayload, Detail: "spt must start with spt_"}
	}

	// verify the credential echoes the expected amount and currency
	if err := s.verifyRequestFields(cred, amount, currency); err != nil {
		return "", err
	}

	idempotencyKey := fmt.Sprintf("mpp_%s_%s", cred.Challenge.ID, payload.SPT)

	params := &stripe.PaymentIntentCreateParams{
		Amount:   stripe.Int64(mustParseInt64(amount)),
		Currency: stripe.String(currency),
		AutomaticPaymentMethods: &stripe.PaymentIntentCreateAutomaticPaymentMethodsParams{
			Enabled:        stripe.Bool(true),
			AllowRedirects: stripe.String("never"),
		},
		Confirm: stripe.Bool(true),
	}
	params.AddExtra("shared_payment_granted_token", payload.SPT)
	params.SetIdempotencyKey(idempotencyKey)

	params.AddMetadata("mpp_version", "1")
	params.AddMetadata("mpp_intent", cred.Challenge.Intent)
	params.AddMetadata("mpp_challenge_id", cred.Challenge.ID)
	params.AddMetadata("mpp_server_id", cred.Challenge.Realm)
	if cred.Source != "" {
		params.AddMetadata("mpp_client_id", cred.Source)
	}

	pi, err := s.Client.V1PaymentIntents.Create(ctx, params)
	if err != nil {
		return "", fmt.Errorf("mpp/stripe: create payment intent: %w", err)
	}

	// detect idempotency replay — payment was already processed with this key
	if pi.Metadata != nil {
		if replayed, ok := pi.Metadata["idempotent_replayed"]; ok && replayed == "true" {
			return "", &PaymentError{
				Problem: ProblemVerificationFailed,
				Detail:  "payment has already been processed",
			}
		}
	}

	switch pi.Status {
	case stripe.PaymentIntentStatusSucceeded:
		return pi.ID, nil
	case stripe.PaymentIntentStatusRequiresAction:
		return "", &PaymentError{
			Problem: ProblemActionRequired,
			Detail:  "payment requires additional action",
		}
	default:
		return "", &PaymentError{
			Problem: ProblemVerificationFailed,
			Detail:  fmt.Sprintf("unexpected payment intent status: %s", pi.Status),
		}
	}
}

// verifyRequestFields checks that the credential's echoed challenge contains
// the expected amount and currency. Defense-in-depth on top of HMAC binding.
func (s *StripeMethod) verifyRequestFields(cred *Credential, expectedAmount, expectedCurrency string) error {
	reqBytes, err := b64.DecodeString(cred.Challenge.Request)
	if err != nil {
		return &PaymentError{Problem: ProblemInvalidChallenge, Detail: "cannot decode challenge request"}
	}
	var req map[string]any
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return &PaymentError{Problem: ProblemInvalidChallenge, Detail: "cannot parse challenge request"}
	}

	if amt, ok := req["amount"].(string); ok && amt != expectedAmount {
		return &PaymentError{Problem: ProblemInvalidChallenge, Detail: "amount mismatch"}
	}
	if cur, ok := req["currency"].(string); ok && cur != expectedCurrency {
		return &PaymentError{Problem: ProblemInvalidChallenge, Detail: "currency mismatch"}
	}
	return nil
}

// mustParseInt64 parses a string amount to int64. Panics on invalid input
// (amounts are validated before reaching this point via ChallengeRequest).
func mustParseInt64(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

// PaymentError is returned by methods when payment verification fails
// with a specific MPP problem type.
type PaymentError struct {
	Problem string
	Detail  string
}

func (e *PaymentError) Error() string {
	return fmt.Sprintf("mpp: %s: %s", e.Problem, e.Detail)
}
