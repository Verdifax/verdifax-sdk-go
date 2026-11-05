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

| Method | Endpoint | Auth |
| --- | --- | --- |
| `Health(ctx)` | `GET /health` | none |
| `Version(ctx)` | `GET /version` | none |
| `GetOpenAPI(ctx)` | `GET /openapi.json` | none |
| `GetStats(ctx)` | `GET /stats` | required |
| `Execute(ctx, req)` | `POST /execute` | required |
| `Attest(ctx, req)` | `POST /execute` | required |
| `AttestClaudeResponse(ctx, ...)` | `POST /execute` | required |
| `AttestOpenAIResponse(ctx, ...)` | `POST /execute` | required |
| `ExecuteBatch(ctx, runs)` | `POST /execute/batch` | required |
| `VerifyDeterminism(ctx, req)` | `POST /execute/verify-determinism` | required |
| `GetRun(ctx, id)` | `GET /runs/{id}` | required |
| `VerifyRun(ctx, id)` | `GET /runs/{id}/verify` | required |
| `ListRuns(ctx, params)` | `GET /runs` | required |
| `SearchRuns(ctx, params)` | `GET /runs/search` | required |
| `ExportRuns(ctx, params)` | `GET /runs/export` | required |
| `ExportRunsCSV(ctx, params)` | `GET /runs/export?format=csv` | required |
| `GetRunArtifacts(ctx, id)` | `GET /runs/{id}/artifacts` | required |
| `GetRunReport(ctx, id)` | `GET /runs/{id}/report` | required |
| `DownloadAuditPDF(ctx, id, format, w)` | `GET /runs/{id}/report.pdf` | required |
| `GetAllowToken(ctx, id)` | `GET /runs/{id}/allow-token` | required |
| `GetDenyReceipt(ctx, id)` | `GET /runs/{id}/deny-receipt` | required |
| `GetCCVHaltReceipt(ctx, id)` | `GET /runs/{id}/ccv-halt-receipt` | required |
| `GetMACCHaltReceipt(ctx, id)` | `GET /runs/{id}/macc-halt-receipt` | required |
| `GetAivpT4HaltReceipt(ctx, id)` | `GET /runs/{id}/aivp-t4-halt-receipt` | required |
| `GetAttestationGapReceipt(ctx, id)` | `GET /runs/{id}/attestation-gap-receipt` | required |
| `GetCESAuditRecord(ctx, id)` | `GET /runs/{id}/ces-audit-record` | required |
| `ListDeletionReceipts(ctx, id)` | `GET /runs/{id}/deletion-receipts` | required |
| `ListAttestations(ctx, params)` | `GET /attestations` | required |
| `GetAttestation(ctx, id)` | `GET /attestations/{id}` | required |
| `GetPublicBundle(ctx, id)` | `GET /runs/{id}/bundle.json` | none |
| `GetPublicBundleByToken(ctx, token)` | `GET /public/runs/{token}/bundle.json` | none |
| `DCAEVerify(ctx, bundle)` | `POST /dcae/verify` | none |
| `RegisterRequestKey(ctx)` | `POST /keys/request-key` | required |
| `ClearRequestKey(ctx)` | `DELETE /keys/request-key` | required |
| `AdminCreateKey(ctx, name)` | `POST /admin/keys` | admin |
| `AdminListKeys(ctx)` | `GET /admin/keys` | admin |
| `AdminRevokeKey(ctx, id)` | `DELETE /admin/keys/{id}` | admin |
| `AdminErase(ctx, req)` | `POST /admin/erase` | admin |

These functions make no request: `CaptureEnvironment`, `FormatProviderPayload`, `SignRequest`, `RequestKeyRegistrationBody`, `RequestSignaturePreimage`, `GenerateRequestKey`, `ValidateHex64`, `ValidateRouteID`, `DSEDispatchHash`, `DCAEClosureHash` and `CRESReceiptHash`. `RunStatuses` lists every run status the server uses.

`GetRunArtifacts`, `GetPublicBundle` and `GetPublicBundleByToken` return the exact JSON bytes the server sent, so you can save them and check them with `verdifax-verify`.

## Versioning

From 1.0, a breaking change needs a new major version.

## Settings

`NewClient` takes a `Config`. `FromEnv()` reads the same settings from the environment.

| Setting | Config field | Environment variable | Default |
| --- | --- | --- | --- |
| Base URL | `BaseURL` | `VERDIFAX_BASE_URL`, then `VERDIFAX_API_URL` | `https://api.verdifax.com` |
| API key | `APIKey` | `VERDIFAX_API_KEY` | none |
| Timeout | `Timeout` | `VERDIFAX_TIMEOUT_MS` | 90 seconds |
| User agent | `UserAgent` | `VERDIFAX_USER_AGENT` | `verdifax-sdk-go/<version>` |
| Retries | `MaxRetries` | `VERDIFAX_MAX_RETRIES` | 3 |
| First retry delay | `RetryBaseDelay` | none | 200 ms |

GET, HEAD and OPTIONS requests are retried after a network failure or an HTTP 429, 502, 503 or 504, with exponential backoff and full jitter. POST is never retried. In `Config`, set `MaxRetries` to a negative number to turn retries off; `VERDIFAX_MAX_RETRIES=0` also turns them off. A caller-supplied `HTTPClient` is used as it is, with no retries added.

## Batch runs

`ExecuteBatch` sends up to 1,000 runs in one request and refuses more before sending anything. A row that fails comes back in `Results` with `OK` false, so the call does not return an error for it.

```go
batch, err := client.ExecuteBatch(ctx, []verdifax.ExecuteRequest{
    {ProgramID: programID, RouteID: routeID, RegistryRecordHash: recordHash, PayloadText: "first"},
    {ProgramID: programID, RouteID: routeID, RegistryRecordHash: recordHash, PayloadText: "second"},
})
if err != nil {
    log.Fatal(err)
}
for _, row := range batch.Results {
    fmt.Println(row.Index, row.OK, row.RunID, row.Error)
}
```

`Config.Timeout` covers the whole batch, so raise it for a large one. A batch is one POST and it is never retried. After a timeout the server may have run some or all of the rows, so list your runs before you send them again.

## Evidence export

`ExportRuns` lists the runs the server holds for your key in a period, failures included, with up to 10,000 rows per export. `ExportRunsCSV` returns the same rows as raw CSV text.

```go
period := &verdifax.ExportRunsParams{From: "2026-11-01T00:00:00Z", To: "2026-12-01T00:00:00Z"}

evidence, err := client.ExportRuns(ctx, period)
if err != nil {
    log.Fatal(err)
}
fmt.Println(evidence.Total, evidence.Truncated, evidence.ByStatus)

export, err := client.ExportRunsCSV(ctx, period)
if err != nil {
    log.Fatal(err)
}
if export.Truncated {
    fmt.Printf("The CSV holds part of %d runs. Use a narrower period.\n", export.Total)
}
```

The export states what the server stored, not a verdict. A call that never reached Verdifax cannot appear in it. Both forms say when a period holds more rows than the export returned: check `Truncated`. `ExportRunsCSV` reads `Total` and `Truncated` from the `X-Verdifax-Total` and `X-Verdifax-Truncated` response headers, and returns an error if the server does not send them. In the CSV, a `route_id` that a spreadsheet could read as a formula gets a leading `'`.

## Provider helpers

`AttestClaudeResponse` and `AttestOpenAIResponse` attest a prompt and response as one payload: canonical JSON, exactly `{"prompt":...,"provider":...,"response":...}` with sorted keys and no extra whitespace, UTF-8, with `provider` set to `anthropic` or `openai`. `FormatProviderPayload` builds that text. All four Verdifax SDKs produce the same bytes. A helper call from an earlier version used a different payload, so it gave a different hash for the same text; records already stored are not touched.

```go
run, err := client.AttestClaudeResponse(ctx, programID, routeID, recordHash,
    "What is the boiling point of water?", "100 C at sea level.",
    verdifax.WithGovern())
```

The helpers no longer send AI output for review unless you ask, which changes earlier behavior. Pass `verdifax.WithGovern()` to also send the response text as `AIOutputText` for the AIVP review, which runs on Anthropic in production.

## Optional execute fields

`ExecuteRequest` and `AttestRequest` accept `AttestedContext`, `ReproducibilityContext`, `RequestSubstance`, `AuthorizationChain`, `RegulatoryScaffolding` and `CausalGraph`, on `Execute`, `Attest`, `ExecuteBatch` and `VerifyDeterminism`. Each is recorded as supplied and Verdifax does not check it. The client derives `attested` and `Declared` from the fields you provide. Leave out `origin.source_ip_hash` and `origin.user_agent_hash` in `RequestSubstance`: the server computes them. `Execute`, `Attest` and `VerifyDeterminism` refuse them before sending, and a batch row that sets them fails in `Results`.

`Execute`, `Attest` and `VerifyDeterminism` check that `ProgramID` and `RegistryRecordHash` are 64 lowercase hex characters and that `RouteID` is 1 to 256 printable ASCII characters.

## Environment capture

`CaptureEnvironment(opts)` records the Go version, the platform, the module dependencies built into the binary, the git commit and any seeds you declare. Set the result as `ReproducibilityContext` on an `ExecuteRequest` or `AttestRequest`. Detection is best effort, and a value it cannot read is left out. The server records these values as given and does not check them.

## Determinism check

`VerifyDeterminism` runs one payload twice on the server and compares the manifest hashes. `Deterministic` is true when both runs ended `ok` and the two hashes match. Both runs are recorded, with the status `probe`.

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

// Execute, Attest, AttestClaudeResponse, AttestOpenAIResponse, ExecuteBatch
// and VerifyDeterminism now sign.
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

In a batch each row carries its own signature and nonce, and the server checks them as it reaches that row. A row refused for its signature comes back in `Results`, so a repeated batch returns HTTP 200 with failed rows, and a row reached more than five minutes after it was signed fails the same way. A determinism check uses one signature for the request, and repeating it returns HTTP 403.

The signature shows the holder of the key requested the run. It does not show the key holder accepted the outcome.

## Trust model

This SDK only mediates HTTP I/O, it does NOT verify sealed
manifests on its own. For offline verification with no Verdifax
dependency, use the open-source [`verdifax-verify`](https://github.com/Verdifax/verdifax-verify)
CLI, v0.17.2 or later (signed binaries with SLSA provenance on its GitHub
Releases), which checks both audit bundles and deny or halt receipts.

## License

MIT, see [LICENSE](LICENSE).
