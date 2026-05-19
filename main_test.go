package main

import (
	"context"
	"strings"
	"testing"
)

func TestFilterPII_TokenizesEverySSNInText(t *testing.T) {
	text := "Alice's SSN is 123-45-6789 and Bob's is 987-65-4321. " +
		"Repeat: 123-45-6789. No SSN here."

	got, err := filterPII(context.Background(), map[string]interface{}{"text": text})
	if err != nil {
		t.Fatalf("filterPII returned error: %v", err)
	}

	found, ok := got["ssns_found"].([]interface{})
	if !ok {
		t.Fatalf("ssns_found not a slice: %T", got["ssns_found"])
	}
	if len(found) != 3 {
		t.Fatalf("expected 3 SSN occurrences, got %d (%v)", len(found), found)
	}

	tokens, ok := got["tokens"].(map[string]interface{})
	if !ok {
		t.Fatalf("tokens not a map: %T", got["tokens"])
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 unique tokens, got %d (%v)", len(tokens), tokens)
	}
	t1, _ := tokens["123-45-6789"].(string)
	t2, _ := tokens["987-65-4321"].(string)
	if t1 == "" || t2 == "" {
		t.Fatalf("missing token: %v", tokens)
	}
	if t1 == t2 {
		t.Fatalf("expected distinct tokens for distinct SSNs, both = %s", t1)
	}
	for _, tok := range []string{t1, t2} {
		if !strings.HasPrefix(tok, "TOKEN-ID-") || len(tok) != len("TOKEN-ID-0000") {
			t.Fatalf("unexpected token format: %q", tok)
		}
	}
}

func TestFilterPII_NoSSN(t *testing.T) {
	got, err := filterPII(context.Background(), map[string]interface{}{
		"text": "Just some harmless text with no identifiers at all.",
	})
	if err != nil {
		t.Fatalf("filterPII returned error: %v", err)
	}

	if found, ok := got["ssns_found"].([]interface{}); ok && len(found) != 0 {
		t.Fatalf("expected no SSNs, got %v", found)
	}
	if tokens, ok := got["tokens"].(map[string]interface{}); ok && len(tokens) != 0 {
		t.Fatalf("expected no tokens, got %v", tokens)
	}
}
