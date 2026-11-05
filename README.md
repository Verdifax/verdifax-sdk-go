# verdifax-sdk-go

The official Go SDK for the [Verdifax](https://verdifax.com)
orchestrator REST API.

## Install

```bash
go get github.com/Verdifax/verdifax-sdk-go
```

## Quickstart

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/Verdifax/verdifax-sdk-go"
)

func main() {
    client, err := verdifax.NewClient(verdifax.Config{
        BaseURL: "https://api.verdifax.com",
        APIKey:  os.Getenv("VERDIFAX_API_KEY"),
    })
    if err != nil {
        log.Fatal(err)
    }

    // Attest a decision through the pipeline.
    run, err := client.Execute(context.Background(), &verdifax.ExecuteRequest{
        ProgramID:          "1111111111111111111111111111111111111111111111111111111111111111",
        RouteID:            "demo-attestation",
        RegistryRecordHash: "2222222222222222222222222222222222222222222222222222222222222222",
        PayloadText:        "first attestation",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Sealed run %d, manifest hash %s\n",
        run.RunID, run.Manifest.ManifestHash)

    // Verify the seal recomputes correctly.
    v, err := client.VerifyRun(context.Background(), run.RunID)
    if err != nil {
        log.Fatal(err)
    }
    if v.Verified {
        fmt.Println("✓ Manifest hash recomputes.")
    }
}
```

## What this SDK covers

- `Health(ctx)`, `/health`, anonymous liveness probe + git SHA
- `Version(ctx)`, `/version`, deploy attestation surface
- `Execute(ctx, req)`, `POST /execute`, the core pipeline-execution flow
- `GetRun(ctx, id)`, `GET /runs/{id}`, fetch a sealed run
- `VerifyRun(ctx, id)`, `GET /runs/{id}/verify`, re-derive the seal
- `RegisterRequestKey(ctx)`, `POST /keys/request-key`, require request signatures
- `ClearRequestKey(ctx)`, `DELETE /keys/request-key`, stop requiring them

The full HTTP surface (every endpoint, deletion-receipt list,
DCAE verify, admin endpoints) is documented in the
[OpenAPI spec](https://github.com/Verdifax/verdifax-orchestrator/blob/main/openapi/verdifax.yaml).
This SDK ships the canonical operations; broader coverage lands
as integrators ask.

## Authentication

Every authenticated endpoint expects the API key in the
`X-Verdifax-Key` header. The Client injects it automatically when
the Config carries `APIKey`.

Provision an API key via:

```bash
curl -X POST https://api.verdifax.com/admin/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "go-sdk-prod"}'
```

The response carries the secret **once**, store it immediately.
After that, the orchestrator stores only its hash.

## Request signing

Request signing is optional. A client with no signing key sends the same requests as before.

You can register an Ed25519 public key on your API key, so that each run must also be signed with a private key that only you hold. The key pair is created on your machine, and Verdifax receives only the public key.

```go
// Run once, then store privateKey as a secret. It is 32 raw bytes.
_, privateKey, err := verdifax.GenerateRequestKey()
if err != nil {
    log.Fatal(err)
}

client, err := verdifax.NewClient(verdifax.Config{
    APIKey:     os.Getenv("VERDIFAX_API_KEY"),
    SigningKey: privateKey,
})
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()

// Sends the public key with its proof.
if _, err := client.RegisterRequestKey(ctx); err != nil {
    log.Fatal(err)
}

// Execute, Attest, AttestClaudeResponse and AttestOpenAIResponse now sign.
run, err := client.Execute(ctx, &verdifax.ExecuteRequest{
    ProgramID:          "1111111111111111111111111111111111111111111111111111111111111111",
    RouteID:            "demo-attestation",
    RegistryRecordHash: "2222222222222222222222222222222222222222222222222222222222222222",
    PayloadText:        "first signed attestation",
})

// Stops requiring signatures on this API key.
err = client.ClearRequestKey(ctx)
```

`Config.SigningKey` also accepts the 64 bytes of an `ed25519.PrivateKey`, converted with `verdifax.SigningKey(key)`.

Registering a key changes that API key for every client that uses it: the server then refuses a run without a valid signature, so every caller on the key needs the private key. Each request carries the time and a fresh random nonce. The server refuses a repeated nonce and a time more than five minutes from its own clock.

The signature shows the holder of the key requested the run. It does not show the key holder accepted the outcome.

## Trust model

This SDK only mediates HTTP I/O, it does NOT verify sealed
manifests on its own. For offline verification with no Verdifax
dependency, use the open-source [`verdifax-verify`](https://github.com/Verdifax/verdifax-verify)
CLI, v0.17.2 or later (signed binaries with SLSA provenance on its GitHub
Releases), which checks both audit bundles and deny or halt receipts.

## License

MIT, see [LICENSE](LICENSE).
