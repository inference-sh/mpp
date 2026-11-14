module github.com/inference-sh/mpp/examples/chi

go 1.26.11

// the example builds against the library in this repository
replace github.com/inference-sh/mpp => ../..

require (
	github.com/go-chi/chi/v5 v5.4.0
	github.com/inference-sh/mpp v0.1.1
	github.com/stripe/stripe-go/v84 v84.4.1
)
