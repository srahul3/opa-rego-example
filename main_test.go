package main

import (
	"context"
	"testing"
)

func TestFilterPII_TokenizesSSNAndPassesOtherFields(t *testing.T) {
	input := map[string]interface{}{
		"name": "Jane Doe",
		"role": "Engineer",
		"ssn":  "123-45-6789",
	}

	got, err := filterPII(context.Background(), input)
	if err != nil {
		t.Fatalf("filterPII returned error: %v", err)
	}

	if got["name"] != "Jane Doe" {
		t.Fatalf("expected name to pass through, got %v", got["name"])
	}
	if got["role"] != "Engineer" {
		t.Fatalf("expected role to pass through, got %v", got["role"])
	}
	if got["ssn"] != "XXX-XX-6789-[TOKEN-ID-8819]" {
		t.Fatalf("expected tokenized ssn, got %v", got["ssn"])
	}
}

func TestFilterPII_NoSSN(t *testing.T) {
	input := map[string]interface{}{
		"name": "Jane Doe",
		"role": "Engineer",
	}

	got, err := filterPII(context.Background(), input)
	if err != nil {
		t.Fatalf("filterPII returned error: %v", err)
	}

	if _, ok := got["ssn"]; ok {
		t.Fatalf("did not expect ssn key in output")
	}
	if got["name"] != "Jane Doe" || got["role"] != "Engineer" {
		t.Fatalf("expected non-ssn fields to pass through, got %+v", got)
	}
}
