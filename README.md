# opa-rego-example

Minimal runnable example showing how to scan a block of free-form text for PII
(US SSNs) using **Open Policy Agent (OPA) Rego** combined with a **custom Go
built-in function** that tokenizes each SSN.

## Run

```bash
go mod tidy
go run .
```

## Test

```bash
go test ./...
```

## How it works

1. **Input.** `main` builds `input = { "text": <10-paragraph string with several SSNs> }`.
2. **Rego policy (`pii.filter`).**
   - `regex.find_n(ssn_pattern, input.text, -1)` finds every SSN occurrence
     (`NNN-NN-NNNN`) in the text and exposes them as `ssns_found`.
   - A partial rule iterates `ssns_found` and calls the Go built-in
     `custom.tokenize(ssn)` for each match, building a `tokens` map of
     `ssn -> masked_token` (duplicates collapse because rule keys are unique).
   - The final value `result` bundles both: `ssns_found` and `tokens`.
3. **Go custom built-in.**
   - `custom.tokenize` (registered via `rego.Function1`) takes one SSN string
     and returns `"XXX-XX-<last4>-[TOKEN-ID-8819]"`.
4. **Evaluation.** `filterPII` calls `rego.New(...).PrepareForEval(ctx)` and
   then `Eval(ctx, rego.EvalInput(input))`. The query
   `data.pii.filter.result` returns a `map[string]interface{}` that `main`
   prints: the original text, the list of detected SSNs, and the
   SSN→token map.

## Why split work between Rego and Go?

- **Rego** is great at declarative structural logic: "for every match, do X",
  collecting things into sets/maps, and expressing policy decisions.
- **Go built-ins** are the right tool for stateful or performance-sensitive
  operations (calling a real tokenization service, hitting a KMS, etc.).
  The policy stays declarative while the host application controls the
  side-effecting bits.
