// Demo server showing MPP payments on a chi router.
//
// Run:
//
//	STRIPE_SECRET_KEY=sk_test_... STRIPE_PROFILE_ID=profile_test_... go run .
//
// Test without payment (gets 402 challenge):
//
//	curl -i http://localhost:8080/v1/generate
//
// Test with the API key (FallthroughAuth accepts it, no payment):
//
//	curl -i -X POST -H "Authorization: Bearer my-api-key" http://localhost:8080/v1/generate
//
// Test with any other key (gets the 402 challenge, like no key at all):
//
//	curl -i -X POST -H "Authorization: Bearer wrong" http://localhost:8080/v1/generate
//
// The key is API_KEY, "my-api-key" if unset.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/inference-sh/mpp"
	"github.com/stripe/stripe-go/v84"
)

func main() {
	stripeKey := os.Getenv("STRIPE_SECRET_KEY")
	profileID := os.Getenv("STRIPE_PROFILE_ID")

	if stripeKey == "" || profileID == "" {
		log.Fatal("set STRIPE_SECRET_KEY and STRIPE_PROFILE_ID")
	}

	// the one API key this demo accepts. a real server looks keys up in its
	// own store
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		apiKey = "my-api-key"
	}

	// generate HMAC secret for signing challenges
	secretKey := make([]byte, 32)
	if _, err := rand.Read(secretKey); err != nil {
		log.Fatal(err)
	}

	// configure the MPP middleware
	pay := mpp.Middleware(mpp.Config{
		SecretKey: secretKey,
		Realm:     "api.example.com",

		Methods: []mpp.Method{
			&mpp.StripeMethod{
				Client:             stripe.NewClient(stripeKey),
				NetworkID:          profileID,
				PaymentMethodTypes: []string{"card", "link"},
			},
		},

		// price each request — in production, look up the app/model and
		// evaluate your pricing formula here
		Price: func(r *http.Request) (string, string, error) {
			return "50", "usd", nil // 50 cents
		},

		// record payment in your billing system
		OnPayment: func(ctx context.Context, receipt *mpp.Receipt, cred *mpp.Credential, amount, currency string) error {
			log.Printf("payment received: %s %s %s (ref: %s, source: %s)",
				receipt.Method, amount, currency, receipt.Reference, cred.Source)
			return nil
		},

		// serve a request without payment only if it carries the API key.
		// this check is what keeps the route paid: a header the function
		// does not accept gets the 402 challenge
		FallthroughAuth: func(r *http.Request) bool {
			got := r.Header.Get("Authorization")
			return subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+apiKey)) == 1
		},
	})

	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	// public endpoints — no payment required
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	// paid endpoints — MPP middleware gates access
	r.Route("/v1", func(r chi.Router) {
		r.Use(pay) // every route in /v1 requires payment, or the API key (FallthroughAuth)

		r.Post("/generate", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			// check how the request was authenticated
			if receipt := mpp.ReceiptFromContext(r.Context()); receipt != nil {
				// paid via MPP
				json.NewEncoder(w).Encode(map[string]any{
					"result":  "generated content here",
					"paid":    true,
					"method":  receipt.Method,
					"receipt": receipt.Reference,
				})
			} else {
				// no payment: FallthroughAuth accepted the API key
				json.NewEncoder(w).Encode(map[string]any{
					"result": "generated content here",
					"paid":   false,
					"auth":   "api_key",
				})
			}
		})

		r.Get("/models", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"models": []string{"flux-1.1-pro", "sdxl", "gemini-3-flash"},
			})
		})
	})

	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}
