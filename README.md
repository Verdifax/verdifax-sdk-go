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
        fmt.Println("✓ Manifest hash recomputes, run is intact.")
    }
}
```

## What this SDK covers

- `Health(ctx)`, `/health`, anonymous liveness probe + git SHA
- `Version(ctx)`, `/version`, deploy attestation surface
- `Execute(ctx, req)`, `POST /execute`, the core pipeline-execution flow
- `GetRun(ctx, id)`, `GET /runs/{id}`, fetch a sealed run
- `VerifyRun(ctx, id)`, `GET /runs/{id}/verify`, re-derive the seal

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

## Trust model

This SDK only mediates HTTP I/O, it does NOT verify sealed
manifests on its own. For offline verification with no Verdifax
dependency, use the open-source [`verdifax-verify`](https://github.com/Verdifax/verdifax-verify)
CLI, v0.17.2 or later (signed binaries with SLSA provenance on its GitHub
Releases), which checks both audit bundles and deny or halt receipts.

## License

MIT, see [LICENSE](LICENSE).
