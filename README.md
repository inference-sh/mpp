# mpp

go middleware for the [machine payments protocol](https://mpp.dev) (MPP).

agents pay per-request via HTTP 402 challenge-credential-receipt exchanges. no accounts, no API keys — just pay and go.

implements [draft-ryan-httpauth-payment-01](https://datatracker.ietf.org/doc/draft-ryan-httpauth-payment/) (IETF).

## install

```
go get github.com/inference-sh/mpp
```

## quick start with chi

```go
pay := mpp.Middleware(mpp.Config{
    SecretKey: secretKey,
    Realm:     "api.example.com",
    Methods: []mpp.Method{
        &mpp.StripeMethod{
            Client:             stripe.NewClient("sk_live_..."),
            NetworkID:          "profile_xxx",
            PaymentMethodTypes: []string{"card", "link"},
        },
    },
    Price: func(r *http.Request) (string, string, error) {
        return "50", "usd", nil // 50 cents
    },
    AllowFallthrough: true, // let Bearer API key requests pass through
})

r := chi.NewRouter()
r.Route("/v1", func(r chi.Router) {
    r.Use(pay)
    r.Post("/generate", generateHandler)
})
```

full runnable example: [`examples/chi`](examples/chi)

works with chi, gorilla/mux, stdlib `ServeMux`, or any `net/http` compatible router.

## how it works

```
agent                                 your server
  |                                        |
  |  POST /v1/generate                     |
  |---------------------------------------→|
  |                                        |
  |  402 Payment Required                  |
  |  WWW-Authenticate: Payment id="...",   |
  |    method="stripe", amount="50", ...   |
  |←---------------------------------------|
  |                                        |
  |  [agent pays via Stripe SPT]           |
  |                                        |
  |  POST /v1/generate                     |
  |  Authorization: Payment <credential>   |
  |---------------------------------------→|
  |                                        |
  |  200 OK                                |
  |  Payment-Receipt: <receipt>            |
  |←---------------------------------------|
```

## features

- **HMAC-signed challenges** — tamper-proof price binding, constant-time verification
- **multiple payment methods** — stripe SPT (fiat) built-in, implement `Method` interface for tempo, x402, lightning, or custom settlement
- **crypto-ready** — string amounts throughout (no int64 precision loss for wei/lamports), `Method` interface is settlement-agnostic
- **`AllowFallthrough`** — mount on the same route as API key auth. bearer tokens pass through, unauthenticated requests get a 402 challenge. this is the key feature for adding MPP to an existing API without separate routes
- **`OnPayment` callback** — hook into your billing system after payment verification
- **`PriceFn`** — dynamic per-request pricing. look up the resource, evaluate your pricing formula, return the cost
- **context helpers** — `ReceiptFromContext(ctx)` and `CredentialFromContext(ctx)` in your handler
- **defense-in-depth** — HMAC binding + SPT prefix validation + request field verification + idempotency replay detection
- **RFC 9457 problem details** — structured error responses per spec

## demo

```bash
# terminal 1: run the demo server
cd examples/chi
STRIPE_SECRET_KEY=sk_test_... STRIPE_PROFILE_ID=profile_test_... go run .

# terminal 2: hit a paid endpoint (gets 402 challenge)
curl -i http://localhost:8080/v1/generate

# hit with an API key (AllowFallthrough passes through)
curl -i -H "Authorization: Bearer my-api-key" http://localhost:8080/v1/generate

# hit a free endpoint
curl -i http://localhost:8080/health
```

## payment methods

### stripe (built-in)

accepts fiat payments via [shared payment tokens](https://docs.stripe.com/agentic-commerce/concepts/shared-payment-tokens) (SPTs). requires a [Stripe profile](https://dashboard.stripe.com) for the `networkId`.

```go
&mpp.StripeMethod{
    Client:             stripe.NewClient(os.Getenv("STRIPE_SECRET_KEY")),
    NetworkID:          "profile_xxx",
    PaymentMethodTypes: []string{"card", "link"},
    Decimals:           2, // default for USD; set to 6 for USDC
}
```

### custom

implement the `Method` interface to add any payment rail:

```go
type Method interface {
    Name() string
    ChallengeRequest(amount, currency string) map[string]any
    Verify(ctx context.Context, cred *Credential, amount, currency string) (reference string, err error)
}
```

amounts are strings to support both fiat cents and crypto wei/lamports without precision loss.

## license

MIT — [inference.sh](https://inference.sh)
