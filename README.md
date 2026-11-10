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
| `DownloadAuditPDFWithAnswer(ctx, id, format, aiOutputText, w)` | `POST /runs/{id}/report.pdf`: prints the AI's answer when its SHA-256 is the sealed hash | required |
| `DownloadPublicAuditPDF(ctx, token, format, aiOutputText, w)` | `GET` or `POST /public/runs/{token}/report.pdf` | none |
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
| `GetAccount(ctx)` | `GET /account` | owner |
| `CreateAccountKey(ctx, req)` | `POST /account/keys` | owner |
| `ListAccountKeys(ctx)` | `GET /account/keys` | owner |
| `RevokeAccountKey(ctx, id)` | `DELETE /account/keys/{id}` | owner |
| `RegisterAccountRequestKey(ctx)` | `POST /account/request-key` | owner |
| `ClearAccountRequestKey(ctx)` | `DELETE /account/request-key` | owner |
| `ListAccountRuns(ctx, params)` | `GET /account/runs` | owner |
| `ExportAccountRuns(ctx, params)` | `GET /account/runs/export` | owner |
| `ExportAccountRunsCSV(ctx, params)` | `GET /account/runs/export?format=csv` | owner |
| `UploadAccountPolicy(ctx, document)` | `POST /account/policies` | owner |
| `ListAccountPolicies(ctx)` | `GET /account/policies` | owner |
| `GetAccountPolicy(ctx, documentHash)` | `GET /account/policies/{document_hash}` | owner |
| `TestAccountPolicy(ctx, req)` | `POST /account/policies/test` | owner |
| `GetAccountPolicyHistory(ctx)` | `GET /account/policies/history` | owner |
| `ActivateAccountPolicy(ctx, documentHash)` | `GET /account/policies`, then `POST /account/policies/{document_hash}/activate` | owner |
| `RegisterApprover(ctx, req)` | `POST /account/approvers` | owner |
| `ListApprovers(ctx)` | `GET /account/approvers` | owner |
| `RevokeApprover(ctx, id)` | `DELETE /account/approvers/{id}` | owner |
| `GetNewestSignOff(ctx, opts)` | `GET /signoffs/newest`, or with `AsOwner` `GET /account/signoffs/newest` | required, or owner |
| `SignOff(ctx, target, decision, approverKey, opts)` | `GET /signoffs/newest`, then `POST /signoffs`; with `AsOwner` the `/account/signoffs` routes | required, or owner |
| `GetSignOffs(ctx, runID, opts)` | `GET /runs/{id}/signoffs`, or with `AsOwner` `GET /account/runs/{id}/signoffs` | required, or owner |
| `GetSignOffHistory(ctx)` | `GET /account/signoffs/history` | owner |
| `GetSignals(ctx, opts)` | `GET /signals`, or with `AsOwner` `GET /account/signals` | feed key, or owner |
| `FollowSignals(ctx, after, opts, fn)` | `GET /signals` page after page, or with `AsOwner` `GET /account/signals` | feed key, or owner |
| `CreateFeedKey(ctx, name, expiresAt)` | `POST /account/feed-keys` | owner |
| `RevokeFeedKey(ctx, id)` | `DELETE /account/feed-keys/{id}` | owner |
| `CreateWebhook(ctx, url, types)` | `POST /account/webhooks` | owner |
| `ListWebhooks(ctx)` | `GET /account/webhooks` | owner |
| `DeleteWebhook(ctx, id)` | `DELETE /account/webhooks/{id}` | owner |
| `ListWebhookDeliveries(ctx, id, limit)` | `GET /account/webhooks/{id}/deliveries` | owner |
| `GetFailureReceipt(ctx, id)` | `GET /runs/{id}/failure-receipt` | required |
| `AdminCreateKey(ctx, name, opts...)` | `POST /admin/keys` | admin |
| `AdminListKeys(ctx)` | `GET /admin/keys` | admin |
| `AdminRevokeKey(ctx, id)` | `DELETE /admin/keys/{id}` | admin |
| `AdminClearRequestKey(ctx, id)` | `DELETE /admin/keys/{id}/request-key` | admin |
| `AdminErase(ctx, req)` | `POST /admin/erase` | admin |
| `AdminCreateAccount(ctx, req)` | `POST /admin/accounts` | admin |
| `AdminListAccounts(ctx)` | `GET /admin/accounts` | admin |

"owner" means the account's owner key. See [Accounts](#accounts). A feed key reads the signal feed and nothing else. See [Signal feed](#signal-feed).

`client.Job(jobID)` makes no request either. It returns the `Job` that `Step` runs on.

These functions make no request: `CaptureEnvironment`, `FormatProviderPayload`, `SignRequest`, `RequestKeyRegistrationBody`, `RequestSignaturePreimage`, `PolicyActivationPreimage`, `PolicyActivationApproval`, `SignOffPreimage`, `ApproverKeyProof`, `SignalEventHash`, `VerifyWebhook`, `GenerateRequestKey`, `ValidateHex64`, `ValidateRouteID`, `DSEDispatchHash`, `DCAEClosureHash` and `CRESReceiptHash`. `RunStatuses` lists every run status the server uses.

`GetRunArtifacts`, `GetPublicBundle`, `GetPublicBundleByToken`, `GetPolicyHistory`, `GetSignOffHistory` and `GetFailureReceipt` return the exact JSON bytes the server sent, so you can save them and check them with `verdifax-verify`.

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

Set `JobID` on `ExportRunsParams` to export the runs of one job. New rows carry `AnchorSource`, `JobID` and `StepID`. Each row carries `APIKeyID`, the key that requested the run, which is the last CSV column, after `step_id`. Each `RunSummary` from `ListRuns`, `SearchRuns` and `ListAccountRuns` carries it too.

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

## Accounts

An account is a company. Every API key belongs to one account for life. The account's owner key manages the account: it creates and revokes member keys, sets the account policy and reads the runs of every key in the account. An owner key cannot run anything: the server refuses it with HTTP 403 on every route outside `/account` that takes an API key, which comes back as an `*APIError`. Member keys are the keys that run. On a trial account, a member key needs a request key before it can run, as every trial key does.

```go
// An admin creates the account and its first owner key. The secret is shown once.
created, err := admin.AdminCreateAccount(ctx, &verdifax.AdminCreateAccountRequest{Name: "Acme", Tier: "production"})
if err != nil {
    log.Fatal(err)
}
fmt.Println(created.Account.AccountID, created.OwnerKey.Secret)

// The owner signs every change to the account policy, so it needs a request key.
_, ownerSigningKey, err := verdifax.GenerateRequestKey()
if err != nil {
    log.Fatal(err)
}
owner, err := verdifax.NewClient(verdifax.Config{APIKey: created.OwnerKey.Secret, SigningKey: ownerSigningKey})
if err != nil {
    log.Fatal(err)
}
if _, err := owner.RegisterAccountRequestKey(ctx); err != nil {
    log.Fatal(err)
}

// The owner creates member keys. These are the keys that run.
member, err := owner.CreateAccountKey(ctx, &verdifax.CreateAccountKeyRequest{Name: "payments-service"})
if err != nil {
    log.Fatal(err)
}
fmt.Println(member.ID, member.Secret)

// The owner stores and activates the account policy.
text, err := os.ReadFile("account-policy.json")
if err != nil {
    log.Fatal(err)
}
policy, err := owner.UploadAccountPolicy(ctx, string(text))
if err != nil {
    log.Fatal(err)
}
change, err := owner.ActivateAccountPolicy(ctx, policy.DocumentHash)
if err != nil {
    log.Fatal(err)
}
fmt.Println(change.ChainID, change.Sequence)

// The owner exports the runs of every key in the account.
evidence, err := owner.ExportAccountRuns(ctx, &verdifax.ExportRunsParams{From: "2026-11-01T00:00:00Z"})
if err != nil {
    log.Fatal(err)
}
fmt.Println(evidence.AccountID, evidence.Total, evidence.Truncated)
```

What an account is, and what it is not:

- The account number, such as `account-7`, is a label Verdifax assigned. It is not a verified company identity.
- An account policy is the customer's own. Verdifax did not write, review or approve it.
- Every key in the account must pass the account policy on top of its own policy. A run is admitted only when both allow.
- The account's view covers the runs its keys made through Verdifax, not runs made elsewhere.
- An owner key cannot run anything.

`ActivateAccountPolicy` reads `ChainID` (`account-N`) and `NewestActivationHash` with `GET /account/policies`, and signs the change over that chain with the `SigningKey`, as `ActivatePolicy` does. The server refuses an unsigned change to an account policy, so a client without a `SigningKey` gets `ErrSigningKeyRequired` before anything is sent. `PolicyActivationApproval` and `PolicyActivationPreimage` take the account chain the same way. `ClearAccountRequestKey` clears the owner key's request key. With none registered, the server refuses to activate an account policy.

`ExportAccountRuns` returns a `RunsExport`, as `ExportRuns` does. Both carry `AccountID`, and `AccountPolicyDocuments` and `AccountPolicyHistory` once the account has stored a policy. `AccountPolicyHistory` and `GetAccountPolicyHistory` keep the exact JSON bytes the server sent, so save them unchanged. `RevokeAccountKey` returns a `*NotFoundError` for a key in another account and for an owner key.

To put a new customer key in an existing account, an admin passes its number: `admin.AdminCreateKey(ctx, "payments-service", verdifax.AdminCreateKeyOptions{AccountID: 7})`. Without it, the key gets an account of its own. A key never moves to another account.

## Sign-off

A sign-off is a person's decision, approve or reject, on one exact result: a completed run's record, a refused or halted run's receipt, or a whole job by its final step. The approver signs it on your machine with an approver key, and Verdifax logs it on the public log. Each sign-off names the account's sign-off before it, so a removed or reordered sign-off breaks the chain.

```go
// On the approver's machine: a new approver key, and the proof that its
// holder has the private key. Nothing is sent.
_, approverKey, err := verdifax.GenerateRequestKey()
if err != nil {
    log.Fatal(err)
}
publicKey, proof, err := verdifax.ApproverKeyProof(approverKey)
if err != nil {
    log.Fatal(err)
}

// The owner registers the public key with its proof, so the owner never
// holds the approver's private key. The SDK checks the proof first.
approver, err := owner.RegisterApprover(ctx, &verdifax.RegisterApproverRequest{
    Name:      "Dana, credit review",
    PublicKey: publicKey,
    Proof:     proof,
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(approver.ID, approver.PublicKey)

// A record's digest is bundle_anchor.anchored_digest in its bundle.
bundle, err := client.GetRunArtifacts(ctx, runID)
if err != nil {
    log.Fatal(err)
}
var sealed struct {
    BundleAnchor struct {
        AnchoredDigest string `json:"anchored_digest"`
    } `json:"bundle_anchor"`
}
if err := json.Unmarshal(bundle, &sealed); err != nil {
    log.Fatal(err)
}

// The approver signs the decision; a member key submits it. Only the
// note's SHA-256 is sent, never its text.
signOff, err := client.SignOff(ctx, verdifax.SignOffTarget{
    Kind:   verdifax.SignOffTargetRecord,
    RunID:  runID,
    Digest: sealed.BundleAnchor.AnchoredDigest,
}, verdifax.SignOffApprove, approverKey, &verdifax.SignOffOptions{Note: "Checked the income figures."})
if err != nil {
    log.Fatal(err)
}
fmt.Println(signOff.Sequence, signOff.SignOffHash)

// Saves the sign-offs on the run for verdifax-verify --signoff.
signOffs, err := client.GetSignOffs(ctx, runID, nil)
if err != nil {
    log.Fatal(err)
}
saved, err := json.Marshal(signOffs)
if err != nil {
    log.Fatal(err)
}
if err := os.WriteFile("signoffs.json", saved, 0o600); err != nil {
    log.Fatal(err)
}

// The owner saves the account's whole chain for verdifax-verify --signoff-history.
history, err := owner.GetSignOffHistory(ctx)
if err != nil {
    log.Fatal(err)
}
if err := os.WriteFile("signoff-history.json", history, 0o600); err != nil {
    log.Fatal(err)
}
```

Then run `verdifax-verify --signoff signoffs.json` with the record, and `verdifax-verify --signoff-history signoff-history.json` on its own. Since v0.22.0, verdifax-verify reads sign-offs.

What a sign-off is, and what it is not:

- An approver key is registered by the account's owner key, and is never a request key in the same account.
- A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log.
- It does not show the review was careful, the result was right, or who the person is. A key is not an identity, and the approver's name is the owner's label.
- It gates nothing on its own.
- A later sign-off on the same result supersedes the earlier one. Nothing is deleted, and revoking an approver key leaves its earlier sign-offs on the record.
- Verdifax did not review the result.

The target names the result by what its public-log entry covers. A record's `Digest` is its `bundle_anchor.anchored_digest` from `GetRunArtifacts`, a receipt's is its hash, and a job's is its final step's anchored digest, with `JobID` set. The server refuses any other digest.

`RegisterApprover` takes exactly one of `ApproverKey`, the approver's private key, from which it makes the proof on your machine, and `PublicKey` with `Proof`, as `ApproverKeyProof` returns them on the approver's machine. It checks a ready-made proof before sending, and refuses an empty name or one over 200 bytes, and the client's own `SigningKey` as the approver key. No private key is sent.

`SignOff` reads the chain, `account-N`, and the newest sign-off with `GetNewestSignOff`, hashes `Note` on your machine, signs with the approver key, the current time and a fresh nonce, and submits. An empty `Note` means no note: it is not hashed, and no `note_hash` is sent. It returns an error if the record the server sends back differs from what was signed in its signature, approver key, decision, previous sign-off hash or target. It refuses a bad target kind, run ID, digest or decision, a missing approver key, and the client's own `SigningKey` as the approver key, before sending anything. An HTTP 409 comes back as an `*APIError`: the chain moved because another sign-off came first, or the digest is not the result's. It is not retried. A member key uses `/signoffs` and `/runs/{id}/signoffs`. Set `AsOwner` in `SignOffOptions` or `AccountRouteOptions` to use the owner key's `/account` routes. `SignOffPreimage` returns the bytes an approver key signs, and `ApproverKeyProof` builds the registration proof without sending it.

`ExportAccountRuns` carries the account's sign-offs in `SignOffs`, as the exact JSON bytes the server sent.

## Signal feed

Every control signal Verdifax recorded for the account is one event in the account's feed, in order, each with its sealed entry: a refused, halted or failed run, a policy change, a sign-off, an approver key registered or revoked, and a member or feed key created or revoked. Each event's place and the previous event's hash are sealed inside its entry before that entry is anchored on the public log. The feed shows the signals Verdifax recorded for the account. It cannot show a signal Verdifax never recorded.

A feed key reads the feed and nothing else. The owner key creates one with `CreateFeedKey` and revokes it with `RevokeFeedKey`.

```go
// The owner key creates a feed key. Its secret is shown once.
feedKey, err := owner.CreateFeedKey(ctx, "siem", nil)
if err != nil {
    log.Fatal(err)
}
feed, err := verdifax.NewClient(verdifax.Config{APIKey: feedKey.Secret})
if err != nil {
    log.Fatal(err)
}

// Follows the feed from the last sequence already read. Store each
// sequence once its event is handled, and start from it next time.
err = feed.FollowSignals(ctx, lastSequenceRead, nil, func(event verdifax.SignalEvent) error {
    fmt.Println(event.Data.Sequence, event.Data.Kind, event.Data.RunID)
    return nil
})
var stopped *verdifax.FollowSignalsError
if errors.As(err, &stopped) {
    log.Printf("stopped after sequence %d: %v", stopped.After, stopped.Err)
}
```

`GetSignals` reads one page: the events after `After`, oldest first, at most `Limit` (1 to 500, 100 by default), held open up to `Wait` (a whole number of seconds from 0 to 25) when there is no new event yet. The HTTP timeout of a feed read is at least its wait plus 30 seconds, whatever the client's own timeout. `FollowSignals` reads each page from the page before's `next_after`, holds each read open for 25 seconds by default, and retries a failed read with the client's retry policy. It refuses a page that would make it skip or repeat an event. It stops when the handler returns an error or the context ends, with a `*FollowSignalsError` whose `After` is the last sequence the handler finished, so following again from there loses nothing. A handler returns `verdifax.ErrStopFollowing` to stop without an error. Both refuse a bad `After`, `Limit` or `Wait` before sending anything. Set `AsOwner` to read the feed with the owner key on `GET /account/signals`.

`SignalData.Entry` is the sealed entry as the exact JSON bytes the server sent. `json.Marshal` the events you read to a file and check it with `verdifax-verify --signals FILE`. `SignalEventHash` returns an event's hash: the SHA-256 of `verdifax.signal.v1`, the kind, the entry's hash, the account, the sequence and the previous event's hash, joined by zero bytes.

Webhooks push each event to an `https://` address after it is stored, in the same envelope the feed serves, and retry a failed delivery for up to 24 hours. A delivery is a copy: the pull feed and the public log are the record, and a missed delivery is read again from the feed.

```go
// The owner key subscribes. nil types delivers every kind. The secret is
// shown once.
hook, err := owner.CreateWebhook(ctx, "https://hooks.example.com/verdifax",
    []string{verdifax.SignalRunRefused, verdifax.SignalRunHalted, verdifax.SignalRunFailed})
if err != nil {
    log.Fatal(err)
}
webhookSecret := hook.Secret

// checkAuth admits only a delivery signed with this subscription's secret,
// checked against the raw body as received.
checkAuth := func(r *http.Request, body []byte) (*verdifax.SignalEvent, error) {
    return verdifax.VerifyWebhook(r.Header, body, webhookSecret, 0, time.Time{})
}
http.HandleFunc("/verdifax", func(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "the body could not be read", http.StatusBadRequest)
        return
    }
    event, err := checkAuth(r, body)
    if err != nil {
        http.Error(w, "the delivery did not verify", http.StatusUnauthorized)
        return
    }
    fmt.Println(event.Data.Sequence, event.Data.Kind)
    w.WriteHeader(http.StatusNoContent)
})
```

`VerifyWebhook` follows the Standard Webhooks scheme. The secret is `whsec_` and base64. The signed content is `webhook-id`, a dot, `webhook-timestamp`, a dot and the raw body bytes, and any one of the `v1` signatures in `webhook-signature` may match, compared in constant time. It refuses a timestamp more than the tolerance from now in either direction; a tolerance of 0 means 5 minutes, and a zero time means now. Header names may be in any case. Its error says which check failed and never holds the secret.

`CreateWebhook` refuses an address that does not start with `https://`, and a type that is not one of the nine kinds (the `Signal` constants) or is named twice, before sending anything. The server checks the address too, and refuses one that is not https on a public host. An account holds at most ten subscriptions. `ListWebhooks` lists them without their secrets, `DeleteWebhook` ends one, and its undelivered events stay in the feed. `ListWebhookDeliveries` shows each delivery's status, attempts and last answer.

`GetFailureReceipt` returns the sealed failure receipt of a run that failed with a server error, as the exact JSON bytes the server sent. It names the request and the stage that failed. A failed run from before failure receipts comes back as a `*NotFoundError`.

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
