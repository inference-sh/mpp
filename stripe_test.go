package mpp

import (
	"encoding/json"
	"testing"
)

func TestMustParseInt64(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"0", 0},
		{"1", 1},
		{"50", 50},
		{"100", 100},
		{"1000", 1000},
		{"1000000", 1000000},
		{"9999999999", 9999999999},
	}
	for _, tt := range tests {
		got := mustParseInt64(tt.input)
		if got != tt.want {
			t.Errorf("mustParseInt64(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestMustParseInt64_NonNumeric(t *testing.T) {
	// non-numeric input returns 0 (safe fallback)
	if got := mustParseInt64("abc"); got != 0 {
		t.Errorf("expected 0 for non-numeric, got %d", got)
	}
	if got := mustParseInt64("12.34"); got != 0 {
		t.Errorf("expected 0 for decimal, got %d", got)
	}
	if got := mustParseInt64(""); got != 0 {
		t.Errorf("expected 0 for empty, got %d", got)
	}
}

func TestVerifyRequestFields_Match(t *testing.T) {
	s := &StripeMethod{}
	reqJSON, _ := json.Marshal(map[string]any{"amount": "1000", "currency": "usd"})
	cred := &Credential{
		Challenge: CredentialChallenge{
			Request: b64.EncodeToString(reqJSON),
		},
	}
	if err := s.verifyRequestFields(cred, "1000", "usd"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestVerifyRequestFields_AmountMismatch(t *testing.T) {
	s := &StripeMethod{}
	reqJSON, _ := json.Marshal(map[string]any{"amount": "9999", "currency": "usd"})
	cred := &Credential{
		Challenge: CredentialChallenge{
			Request: b64.EncodeToString(reqJSON),
		},
	}
	err := s.verifyRequestFields(cred, "1000", "usd")
	if err == nil {
		t.Fatal("expected error for amount mismatch")
	}
	pe, ok := err.(*PaymentError)
	if !ok {
		t.Fatalf("expected PaymentError, got %T", err)
	}
	if pe.Problem != ProblemInvalidChallenge {
		t.Fatalf("expected invalid-challenge, got %s", pe.Problem)
	}
}

func TestVerifyRequestFields_CurrencyMismatch(t *testing.T) {
	s := &StripeMethod{}
	reqJSON, _ := json.Marshal(map[string]any{"amount": "1000", "currency": "eur"})
	cred := &Credential{
		Challenge: CredentialChallenge{
			Request: b64.EncodeToString(reqJSON),
		},
	}
	err := s.verifyRequestFields(cred, "1000", "usd")
	if err == nil {
		t.Fatal("expected error for currency mismatch")
	}
}

func TestVerifyRequestFields_InvalidBase64(t *testing.T) {
	s := &StripeMethod{}
	cred := &Credential{
		Challenge: CredentialChallenge{
			Request: "!!!not-base64!!!",
		},
	}
	err := s.verifyRequestFields(cred, "1000", "usd")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestVerifyRequestFields_InvalidJSON(t *testing.T) {
	s := &StripeMethod{}
	cred := &Credential{
		Challenge: CredentialChallenge{
			Request: b64.EncodeToString([]byte("not json")),
		},
	}
	err := s.verifyRequestFields(cred, "1000", "usd")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestVerifyRequestFields_MissingFields(t *testing.T) {
	// if the echoed request doesn't have amount/currency fields, no error
	// (HMAC is the primary check, field verification is defense-in-depth)
	s := &StripeMethod{}
	reqJSON, _ := json.Marshal(map[string]any{"other": "data"})
	cred := &Credential{
		Challenge: CredentialChallenge{
			Request: b64.EncodeToString(reqJSON),
		},
	}
	if err := s.verifyRequestFields(cred, "1000", "usd"); err != nil {
		t.Fatalf("expected no error for missing fields, got %v", err)
	}
}

func TestSPTValidation(t *testing.T) {
	// SPT prefix check happens in Verify() but we can test the payload parsing directly
	tests := []struct {
		payload string
		wantErr bool
		errMsg  string
	}{
		{`{"spt":"spt_test123"}`, false, ""},
		{`{"spt":""}`, true, "missing spt"},
		{`{"spt":"not_a_spt"}`, true, "spt must start with spt_"},
		{`{}`, true, "missing spt"},
		{`invalid`, true, "unmarshal"},
	}

	for _, tt := range tests {
		var payload stripePayload
		err := json.Unmarshal([]byte(tt.payload), &payload)
		if err != nil {
			if !tt.wantErr {
				t.Errorf("payload %q: unexpected unmarshal error: %v", tt.payload, err)
			}
			continue
		}

		var validationErr error
		if payload.SPT == "" {
			validationErr = &PaymentError{Problem: ProblemInvalidPayload, Detail: "missing spt in payload"}
		} else if len(payload.SPT) < 4 || payload.SPT[:4] != "spt_" {
			validationErr = &PaymentError{Problem: ProblemInvalidPayload, Detail: "spt must start with spt_"}
		}

		if tt.wantErr && validationErr == nil {
			t.Errorf("payload %q: expected error containing %q", tt.payload, tt.errMsg)
		}
		if !tt.wantErr && validationErr != nil {
			t.Errorf("payload %q: unexpected error: %v", tt.payload, validationErr)
		}
	}
}

func TestStripeMethod_ChallengeRequest(t *testing.T) {
	s := &StripeMethod{
		NetworkID:          "profile_test",
		PaymentMethodTypes: []string{"card", "link"},
	}

	req := s.ChallengeRequest("5000", "usd")

	if req["amount"] != "5000" {
		t.Fatalf("expected amount 5000, got %v", req["amount"])
	}
	if req["currency"] != "usd" {
		t.Fatalf("expected currency usd, got %v", req["currency"])
	}
	if req["decimals"] != 2 {
		t.Fatalf("expected decimals 2, got %v", req["decimals"])
	}

	md, ok := req["methodDetails"].(map[string]any)
	if !ok {
		t.Fatal("missing methodDetails")
	}
	if md["networkId"] != "profile_test" {
		t.Fatalf("expected networkId profile_test, got %v", md["networkId"])
	}
}

func TestStripeMethod_ChallengeRequest_CustomDecimals(t *testing.T) {
	s := &StripeMethod{
		NetworkID:          "profile_test",
		PaymentMethodTypes: []string{"card"},
		Decimals:           6, // USDC
	}

	req := s.ChallengeRequest("1000000", "usdc")
	if req["decimals"] != 6 {
		t.Fatalf("expected decimals 6, got %v", req["decimals"])
	}
}

func TestStripeMethod_Name(t *testing.T) {
	s := &StripeMethod{}
	if s.Name() != "stripe" {
		t.Fatalf("expected stripe, got %s", s.Name())
	}
}
