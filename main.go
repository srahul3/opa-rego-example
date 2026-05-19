package main

import (
	"context"
	"fmt"
	"log"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

const regoModule = `
package pii.filter

filtered_data[k] = v {
input[k]
k != "ssn"
v := input[k]
}

filtered_data["ssn"] = token {
input["ssn"]
token := custom.tokenize(input["ssn"])
}
`

func tokenizeSSN(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	var ssn string
	if err := ast.As(a.Value, &ssn); err != nil {
		return nil, err
	}

	if len(ssn) < 4 {
		return nil, fmt.Errorf("invalid ssn format")
	}

	token := fmt.Sprintf("XXX-XX-%s-[TOKEN-ID-8819]", ssn[len(ssn)-4:])
	return ast.StringTerm(token), nil
}

func filterPII(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	tokenizeDecl := &rego.Function{
		Name: "custom.tokenize",
		Decl: types.NewFunction(types.Args(types.S), types.S),
	}

	r := rego.New(
		rego.Query("data.pii.filter.filtered_data"),
		rego.Module("pii.rego", regoModule),
		rego.Function1(tokenizeDecl, tokenizeSSN),
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

	filtered, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected policy output type %T", rs[0].Expressions[0].Value)
	}

	return filtered, nil
}

func main() {
	ctx := context.Background()

	input := map[string]interface{}{
		"name": "Jane Doe",
		"role": "Engineer",
		"ssn":  "123-45-6789",
	}

	filtered, err := filterPII(ctx, input)
	if err != nil {
		log.Fatalf("failed to filter PII: %v", err)
	}

	fmt.Printf("--- Original Data ---\n%+v\n\n", input)
	fmt.Printf("--- Tokenized Data ---\n%+v\n", filtered)
}
