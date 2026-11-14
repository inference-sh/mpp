package mpp_test

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"

	"github.com/inference-sh/mpp"
	"github.com/stripe/stripe-go/v84"
)

// validAPIKey reports whether an Authorization header carries this server's
// API key. A real server looks the key up in its own store.
func validAPIKey(authorization string) bool {
	const want = "Bearer my-api-key"
	return subtle.ConstantTimeCompare([]byte(authorization), []byte(want)) == 1
}

func Example() {
	// generate a secret key for HMAC-signing challenges
	secretKey := make([]byte, 32)
	if _, err := rand.Read(secretKey); err != nil {
		log.Fatal(err)
	}

	// configure the middleware
	pay := mpp.Middleware(mpp.Config{
		SecretKey: secretKey,
		Realm:     "api.example.com",

		Methods: []mpp.Method{
			&mpp.StripeMethod{
				Client:             stripe.NewClient("sk_test_..."),
				NetworkID:          "profile_xxx", // your Stripe profile ID
				PaymentMethodTypes: []string{"card", "link"},
			},
		},

		// return the price for this request
		Price: func(r *http.Request) (amount, currency string, err error) {
			return "50", "usd", nil // 50 cents = $0.50
		},

		// record the payment in your billing system
		OnPayment: func(ctx context.Context, receipt *mpp.Receipt, cred *mpp.Credential, amount, currency string) error {
			fmt.Printf("payment: %s %s %s (ref: %s)\n", receipt.Method, amount, currency, receipt.Reference)
			return nil
		},

		// serve a request that carries a valid API key without payment.
		// anything else in the Authorization header gets the 402 challenge
		FallthroughAuth: func(r *http.Request) bool {
			return validAPIKey(r.Header.Get("Authorization"))
		},
	})

	// use with any net/http compatible router (chi, gorilla, stdlib)
	mux := http.NewServeMux()
	mux.Handle("/v1/apps/run", pay(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if receipt := mpp.ReceiptFromContext(r.Context()); receipt != nil {
			fmt.Fprintf(w, `{"paid": true, "receipt": %q}`, receipt.Reference)
		} else {
			// no MPP payment: FallthroughAuth accepted the request's API key
			fmt.Fprint(w, `{"paid": false, "auth": "api_key"}`)
		}
	})))

	_ = http.ListenAndServe(":8080", mux)
}
