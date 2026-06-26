package mpp

import "context"

// Method defines the interface for a payment method (Stripe, Tempo, etc.).
// Each method knows how to build challenge requests and verify payment credentials.
//
// Amounts are strings to support both fiat (cents) and crypto (wei, lamports)
// without precision loss. The method implementation interprets the amount format.
type Method interface {
	// Name returns the method identifier (e.g. "stripe", "tempo").
	Name() string

	// ChallengeRequest returns the method-specific payment request fields
	// for a given amount and currency. Amount is a string to support arbitrary
	// precision (e.g. "100" cents, "1000000" wei).
	ChallengeRequest(amount, currency string) map[string]any

	// Verify validates a payment credential and settles the payment.
	// Returns a reference string (e.g. Stripe PaymentIntent ID, tx hash) on success.
	Verify(ctx context.Context, cred *Credential, amount, currency string) (reference string, err error)
}
