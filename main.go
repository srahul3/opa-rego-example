package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

// tokenRegistry assigns a unique sequential token to each unique SSN.
// The same SSN always maps to the same token within one registry instance.
type tokenRegistry struct {
	mu     sync.Mutex
	tokens map[string]string
	next   int
}

func newTokenRegistry() *tokenRegistry {
	return &tokenRegistry{tokens: map[string]string{}}
}

func (r *tokenRegistry) tokenFor(ssn string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tokens[ssn]; ok {
		return t
	}
	r.next++
	t := fmt.Sprintf("TOKEN-ID-%04d", r.next)
	r.tokens[ssn] = t
	return t
}

// regoModule is the Rego policy. It:
//  1. Uses the built-in `regex.find_n` to extract every SSN from input.text.
//  2. For each SSN found, calls the Go-registered custom built-in
//     `custom.tokenize` to convert it into a stable token.
const regoModule = `
package pii.filter

ssn_pattern := ` + "`" + `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b` + "`" + `

# All SSNs that appear in the input text (may contain duplicates).
ssns_found := regex.find_n(ssn_pattern, input.text, -1)

# Map of ssn -> token, built by calling the Go built-in once per unique SSN.
tokens[ssn] = token {
	ssn := ssns_found[_]
	token := custom.tokenize(ssn)
}

result := {
	"ssns_found": ssns_found,
	"tokens":     tokens,
}
`

// tokenizeSSN implements custom.tokenize(ssn) -> string using the given
// registry so that each unique SSN receives a unique sequential token.
func tokenizeSSN(reg *tokenRegistry) rego.Builtin1 {
	return func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
		var ssn string
		if err := ast.As(a.Value, &ssn); err != nil {
			return nil, err
		}
		if len(ssn) == 0 {
			return nil, fmt.Errorf("invalid ssn format: %q", ssn)
		}
		return ast.StringTerm(reg.tokenFor(ssn)), nil
	}
}

func filterPII(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	tokenizeDecl := &rego.Function{
		Name: "custom.tokenize",
		Decl: types.NewFunction(types.Args(types.S), types.S),
	}

	reg := newTokenRegistry()

	r := rego.New(
		rego.Query("data.pii.filter.result"),
		rego.Module("pii.rego", regoModule),
		rego.Function1(tokenizeDecl, tokenizeSSN(reg)),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return map[string]interface{}{}, nil
	}

	out, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected policy output type %T", rs[0].Expressions[0].Value)
	}
	return out, nil
}

// sampleText is a 10-paragraph block containing multiple SSNs.
const sampleText = `Paragraph 1: Jane Doe submitted her onboarding form last Monday. Her primary SSN on file is 123-45-6789, and HR has flagged this record for review by the compliance team.

Paragraph 2: John Smith, a contractor working out of the Boston office, reported a discrepancy in his tax forms. His SSN 987-65-4321 was incorrectly transcribed in the legacy CRM system during the migration.

Paragraph 3: The audit log shows that customer #4471, identified by SSN 555-12-3344, was contacted twice in the same week regarding overdue invoices. This violates the contact frequency policy.

Paragraph 4: During the security review, a stray document was found containing both an email address and the SSN 222-33-4455. The document was quarantined and the owner was notified through standard channels.

Paragraph 5: A merger-related export accidentally included partner records. Among them, partner Acme LLC listed a beneficial owner with SSN 111-22-3333, which should never have left the secure enclave.

Paragraph 6: Support ticket #98821 references a caller who provided 123-45-6789 again, apparently a returning customer. The agent followed protocol and did not store the number in plain text in the ticket body.

Paragraph 7: The data science team requested a sample dataset for model training. They were reminded that fields like SSN 444-55-6677 must be tokenized before any export, even for internal experimentation environments.

Paragraph 8: Legal flagged paragraph 7 above and asked for written confirmation that no raw identifiers, including 444-55-6677 and 555-12-3344, persist in any downstream analytics warehouse table.

Paragraph 9: A penetration test report mentioned that a misconfigured S3 bucket briefly exposed records tied to SSN 777-88-9900. Remediation was completed within four hours and post-mortem actions were scheduled.

Paragraph 10: Finally, leadership approved a new rotation policy: every quarter, sample identifiers such as 123-45-6789, 987-65-4321, and 777-88-9900 will be reviewed to confirm they remain tokenized in all reports.`

func main() {
	ctx := context.Background()

	input := map[string]interface{}{
		"text": sampleText,
	}

	out, err := filterPII(ctx, input)
	if err != nil {
		log.Fatalf("failed to filter PII: %v", err)
	}

	fmt.Println("--- Original Text ---")
	fmt.Println(sampleText)
	fmt.Println()

	fmt.Println("--- SSNs Found (by Rego regex.find_n) ---")
	fmt.Printf("%v\n\n", out["ssns_found"])

	fmt.Println("--- SSN -> Token map (custom.tokenize per match) ---")
	tokens, _ := out["tokens"].(map[string]interface{})
	ssns := make([]string, 0, len(tokens))
	for ssn := range tokens {
		ssns = append(ssns, ssn)
	}
	sort.Slice(ssns, func(i, j int) bool {
		return fmt.Sprint(tokens[ssns[i]]) < fmt.Sprint(tokens[ssns[j]])
	})
	for _, ssn := range ssns {
		fmt.Printf("  %s => %s\n", ssn, tokens[ssn])
	}
	fmt.Println()

	fmt.Println("--- Tokenized Text ---")
	fmt.Println(applyTokens(sampleText, tokens))
}

// applyTokens replaces every SSN in text with its token from the map.
func applyTokens(text string, tokens map[string]interface{}) string {
	for ssn, tok := range tokens {
		if s, ok := tok.(string); ok {
			text = strings.ReplaceAll(text, ssn, s)
		}
	}
	return text
}
