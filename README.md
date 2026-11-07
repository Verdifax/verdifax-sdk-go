# verdifax-sdk-go

The official Go SDK for the [Verdifax](https://verdifax.com)
orchestrator REST API.

## Install

```bash
go get github.com/Verdifax/verdifax-sdk-go
```

## Quickstart

On a trial key, register a request key first and give the client that key: see [Request signing](#request-signing). Without it, a trial key refuses the run.

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
| `job.Step(ctx, stepID, req, opts...)` | `POST /execute` | required |
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
| `UploadPolicy(ctx, document)` | `POST /policies` | required |
| `ListPolicies(ctx)` | `GET /policies` | required |
| `GetPolicy(ctx, documentHash)` | `GET /policies/{document_hash}` | required |
| `TestPolicy(ctx, req)` | `POST /policies/test` | required |
| `GetPolicyHistory(ctx)` | `GET /policies/history` | required |
| `ActivatePolicy(ctx, documentHash)` | `GET /policies`, then `POST /policies/{document_hash}/activate` | required |
| `RegisterRequestKey(ctx)` | `POST /keys/request-key` | required |
| `RotateRequestKey(ctx, newKey)` | `POST /keys/request-key` | required |
| `ClearRequestKey(ctx)` | `DELETE /keys/request-key` | required |
| `AdminCreateKey(ctx, name)` | `POST /admin/keys` | admin |
| `AdminListKeys(ctx)` | `GET /admin/keys` | admin |
| `AdminRevokeKey(ctx, id)` | `DELETE /admin/keys/{id}` | admin |
| `AdminClearRequestKey(ctx, id)` | `DELETE /admin/keys/{id}/request-key` | admin |
| `AdminErase(ctx, req)` | `POST /admin/erase` | admin |

`client.Job(jobID)` makes no request either. It returns the `Job` that `Step` runs on.

These functions make no request: `CaptureEnvironment`, `FormatProviderPayload`, `SignRequest`, `RequestKeyRegistrationBody`, `RequestSignaturePreimage`, `PolicyActivationPreimage`, `PolicyActivationApproval`, `GenerateRequestKey`, `ValidateHex64`, `ValidateRouteID`, `DSEDispatchHash`, `DCAEClosureHash` and `CRESReceiptHash`. `RunStatuses` lists every run status the server uses.

`GetRunArtifacts`, `GetPublicBundle`, `GetPublicBundleByToken` and `GetPolicyHistory` return the exact JSON bytes the server sent, so you can save them and check them with `verdifax-verify`.

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

Set `JobID` on `ExportRunsParams` to export the runs of one job. New rows carry `AnchorSource`, `JobID` and `StepID`.

The export states what the server stored, not a verdict. A call that never reached Verdifax cannot appear in it. Both forms say when a period holds more rows than the export returned: check `Truncated`. `ExportRunsCSV` reads `Total` and `Truncated` from the `X-Verdifax-Total` and `X-Verdifax-Truncated` response headers, and returns an error if the server does not send them. In the CSV, a `route_id` that a spreadsheet could read as a formula gets a leading `'`.

## Jobs

A job is a map of sealed steps. Each step names the records it directly follows, so work can split into branches and join again, and a missing or swapped step is visible.

`client.Job` returns a `Job`, and `Step` takes everything `Attest` takes. This example runs one step, two after it, and a final step joining them:

```go
job, err := client.Job("loan-1")
if err != nil {
    log.Fatal(err)
}

step := func(text string) *verdifax.AttestRequest {
    return &verdifax.AttestRequest{ProgramID: programID, RouteID: routeID, RegistryRecordHash: recordHash, PayloadText: text}
}

if _, err := job.Step(ctx, "intake", step("application received")); err != nil {
    log.Fatal(err)
}
if _, err := job.Step(ctx, "credit", step("credit check"), verdifax.WithAfter("intake")); err != nil {
    log.Fatal(err)
}
if _, err := job.Step(ctx, "fraud", step("fraud check"), verdifax.WithAfter("intake")); err != nil {
    log.Fatal(err)
}
if _, err := job.Step(ctx, "decide", step("decision"), verdifax.WithAfter("credit", "fraud"), verdifax.WithFinal()); err != nil {
    log.Fatal(err)
}

fmt.Println(job.RecordHashes())
```

Without `WithAfter`, a step follows the step run just before it through this `Job`, and the first step follows nothing. `WithAfter()` with no names starts another root step, which follows nothing. Naming a step this `Job` has no record for is refused before anything is sent. `WithExternalPrevious` names records from another account by hash.

`RecordHashes` maps each step id to its record hash, refused and halted steps included. On a client with a `SigningKey`, `SignedRequests` maps each of those step ids to the exact text signed for it. When a step is refused or halted, `Step` records the receipt hash and the signed text from the error, then returns the same error `Attest` returns, with them in `APIError.RecordHash` and `APIError.SignedRequest`. A later step can name that step.

A step that sealed nothing, such as a timeout or a 409, is not recorded and does not change the default `after`. If a successful response has no `record_hash`, `Step` uses its manifest hash. If it has neither, `Step` returns the response together with an error, so the map never silently gets a gap.

A job name or step name is 1 to 128 letters, digits, dots, underscores, colons or dashes, and the SDK refuses any other before sending.

To place a run in a job yourself, set `Job` to a `JobLink` on an `ExecuteRequest`, an `AttestRequest` or a batch row, or pass `verdifax.WithJob(link)` to a provider helper. The SDK sorts `PreviousRecordHashes` and `ExternalPrevious` and removes repeats. Decoding a `JobLink` from JSON refuses an unknown field, a null, a `final` that is not a boolean and a hash list that is not a list, so a typo cannot silently drop a link. `RecordHash` on the response and on each batch result is the hash to name in the next step. `VerifyDeterminism` runs twice, so the server refuses a job there.

A job map covers what was sent. It cannot show a step that was never sent.

## Policies

A policy is your own set of rules for the runs under your API key. You upload its exact text, try it on sample inputs, and then activate it. Each activation is a change record that names the change before it and is anchored on the public log, so the history of your policies can be checked.

Verdifax did not write, review or approve your policy. A pass means the rules ran, not that they are good rules.

```go
text, err := os.ReadFile("policy.json")
if err != nil {
    log.Fatal(err)
}

// Stores the exact text. Nothing changes until it is activated.
policy, err := client.UploadPolicy(ctx, string(text))
if err != nil {
    log.Fatal(err)
}

// Shows which rule would fire on sample inputs. It seals nothing.
trial, err := client.TestPolicy(ctx, &verdifax.PolicyTestRequest{
    DocumentHash: policy.DocumentHash,
    Inputs:       map[string]any{"subject_type": "user", "object_type": "transaction", "mfa_satisfied": false},
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(trial.Outcome, trial.FiredRuleID, trial.ReasonCode)

// Puts it in force.
change, err := client.ActivatePolicy(ctx, policy.DocumentHash)
if err != nil {
    log.Fatal(err)
}
fmt.Println(change.Sequence, change.ActivationHash)

// A run declares what the rules read. The actor values need an attested actor.
run, err := client.Attest(ctx, &verdifax.AttestRequest{
    ProgramID:          programID,
    RouteID:            routeID,
    RegistryRecordHash: recordHash,
    PayloadText:        "transfer 500",
    AttestedContext:    map[string]any{"actor_id": "user-42"},
    PolicyContext: &verdifax.PolicyContext{
        ActorType:      "user",
        MFASatisfied:   true,
        ObjectType:     "transaction",
        Classification: "CONFIDENTIAL",
    },
    ExpectedPolicyHash: policy.PolicyHash,
})

// Rolling back is activating an earlier document.
if _, err := client.ActivatePolicy(ctx, earlierDocumentHash); err != nil {
    log.Fatal(err)
}

// Saves the history of changes, oldest first, for verdifax-verify --policy-history.
history, err := client.GetPolicyHistory(ctx)
if err != nil {
    log.Fatal(err)
}
if err := os.WriteFile("policy-history.json", history, 0o600); err != nil {
    log.Fatal(err)
}
```

Then run `verdifax-verify --policy-history policy-history.json` on the saved file. Save the bytes unchanged.

`UploadPolicy` sends the text exactly as given, because the server hashes those exact bytes as `DocumentHash`. It refuses an empty document and text that is not valid UTF-8, which could not be sent unchanged. `GetPolicy` returns the stored text in `Document` and refuses a hash that is not 64 lowercase hex characters. `TestPolicy` needs exactly one of `Document` and `DocumentHash`, and sends `Inputs` as given.

`ActivatePolicy` reads `ChainID` and `NewestActivationHash` with `GET /policies` and names that change. A client with a `SigningKey` also signs the change with it, which the server requires once a request key is registered. A client without one sends no signature. A rollback is one more change, so the change it undoes stays on the record. An HTTP 409 comes back as an `*APIError` with the server's message: the chain moved because another change came first, or the document is not yet effective. It is not retried. `PolicyActivationApproval` builds the same signature without sending it, and `PolicyActivationPreimage` returns the bytes it signs.

`PolicyContext` takes `ActorType` (`agent`, `user`, `service` or `system`), `MFASatisfied`, `SessionAgeSeconds` (not negative), `ObjectType` (`text`, `transaction`, `code`, `data`, `model` or `file`), `ObjectID` (at most 256 bytes) and `Classification` (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, `TOP_SECRET` or `TS_SCI`). `ActorType`, `MFASatisfied` and `SessionAgeSeconds` describe the attested actor, so a run that sets one of them must also carry `AttestedContext` with the actor; `ObjectType`, `ObjectID` and `Classification` work without it. `ExpectedPolicyHash` names the policy hash the run expects: when another policy is active, the server refuses the run with HTTP 409. The SDK refuses a value outside these before sending, on `Execute`, `Attest`, each batch row, `VerifyDeterminism`, `Job.Step` and the provider helpers. Decoding a `PolicyContext` from JSON refuses an unknown field, a null and a value of the wrong type, so a misspelt field is never dropped. On a client with a `SigningKey`, both fields are inside `signed_request`.

A policy judges what you declared. It cannot show the declared facts are true.

A refusal stops the action only if your system waits for the answer.

## Provider helpers

`AttestClaudeResponse` and `AttestOpenAIResponse` attest a prompt and response as one payload: canonical JSON, exactly `{"prompt":...,"provider":...,"response":...}` with sorted keys and no extra whitespace, UTF-8, with `provider` set to `anthropic` or `openai`. `FormatProviderPayload` builds that text. All four Verdifax SDKs produce the same bytes. A helper call from an earlier version used a different payload, so it gave a different hash for the same text; records already stored are not touched.

```go
run, err := client.AttestClaudeResponse(ctx, programID, routeID, recordHash,
    "What is the boiling point of water?", "100 C at sea level.",
    verdifax.WithGovern())
```

The helpers no longer send AI output for review unless you ask, which changes earlier behavior. Pass `verdifax.WithGovern()` to also send the response text as `AIOutputText` for the AIVP review, which runs on Anthropic in production.

Pass `verdifax.WithPolicyContext(policyContext)` and `verdifax.WithExpectedPolicyHash(policyHash)` to set the policy fields described under Policies. The helpers send an `AttestedContext`, so the actor values are accepted.

Pass `verdifax.WithJob(link)` to place the response in a job. `RecordHash` and `SignedRequest` come back as they do from `Attest`, and on the `APIError` of a refused or halted run.

## Optional execute fields

`ExecuteRequest` and `AttestRequest` accept `AttestedContext`, `ReproducibilityContext`, `RequestSubstance`, `AuthorizationChain`, `RegulatoryScaffolding` and `CausalGraph`, on `Execute`, `Attest`, `ExecuteBatch` and `VerifyDeterminism`. Each is recorded as supplied and Verdifax does not check it. The client derives `attested` and `Declared` from the fields you provide. Leave out `origin.source_ip_hash` and `origin.user_agent_hash` in `RequestSubstance`: the server computes them. `Execute`, `Attest` and `VerifyDeterminism` refuse them before sending, and a batch row that sets them fails in `Results`.

They also accept `PolicyContext` and `ExpectedPolicyHash`, which the SDK checks before sending, as described under Policies.

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

A trial key, which is what a pilot receives, needs a request key: it seals nothing until one is registered, and the key can then be replaced but not cleared. On a production key, request signing is optional, and a client with no signing key sends the same requests as before.

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

// Replaces the key. The current key approves the change, and this client
// then signs with the new key.
_, newKey, err := verdifax.GenerateRequestKey()
if err != nil {
    log.Fatal(err)
}
if _, err := client.RotateRequestKey(ctx, newKey); err != nil {
    log.Fatal(err)
}

// Stops requiring signatures on this API key. The current key approves it,
// and this client then drops its key and sends unsigned requests.
err = client.ClearRequestKey(ctx)
```

`Config.SigningKey` also accepts the 64 bytes of an `ed25519.PrivateKey`, converted with `verdifax.SigningKey(key)`.

Registering a key changes that API key for every client that uses it: the server then refuses a run without a valid signature, so every caller on the key needs the private key. Each request carries the time and a fresh random nonce. The server refuses a repeated nonce and a time more than five minutes from its own clock.

In a batch each row carries its own signature and nonce, and the server checks them as it reaches that row. A row refused for its signature comes back in `Results`, so a repeated batch returns HTTP 200 with failed rows, and a row reached more than five minutes after it was signed fails the same way. A determinism check uses one signature for the request, and repeating it returns HTTP 403.

The SDK signs in version 2: it serializes the request once and signs those exact bytes, which also cover any job block. A signed call sends only `signed_request`, that text as a string, and `request_signature`. `SignedRequest` on the response, on each batch result, on a determinism response and on the `APIError` of a refused or halted run holds the exact text. To check a record against it, save it unchanged to a file and pass the file to `verdifax-verify --request FILE`. `SignRequest` still returns the version 1 form, which cannot carry a job.

Once a key is registered, the server needs that key's approval to replace or clear it, so `RotateRequestKey` and `ClearRequestKey` need the current key as `Config.SigningKey`. If `RotateRequestKey` times out, the server may have made the change, so try the new key. After `ClearRequestKey` succeeds, the client drops its signing key and sends unsigned requests, because the server refuses a signature on an API key with no registered key. `AdminClearRequestKey` clears the key on an API key by ID, for a holder who lost it. The ID can name any API key, so the calling client keeps its own signing key.

A signature shows who requested the run, not that they accepted the outcome.

## Trust model

This SDK only mediates HTTP I/O, it does NOT verify sealed
manifests on its own. For offline verification with no Verdifax
dependency, use the open-source [`verdifax-verify`](https://github.com/Verdifax/verdifax-verify)
CLI, v0.17.2 or later (signed binaries with SLSA provenance on its GitHub
Releases), which checks both audit bundles and deny or halt receipts.

## License

MIT, see [LICENSE](LICENSE).
