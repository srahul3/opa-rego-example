# opa-rego-example

Minimal runnable example showing how to tokenize PII (SSN) with Open Policy Agent (OPA) Rego plus a custom Go built-in function.

## Run

```bash
go mod tidy
go run .
```

## Test

```bash
go test ./...
```

## Approach

- Rego handles structural logic (copy non-SSN fields and process `ssn` specially).
- Go registers `custom.tokenize` via `rego.Function1` and performs tokenization logic.

A pure Rego masking alternative (when no external/stateful tokenizer is needed) can use `regex.replace`.
