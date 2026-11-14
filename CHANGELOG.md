# Changelog

## 1.16.0

Webhook changes signed by the owner and sealed in the feed.

- From verifier v0.35.0's server release on, a webhook is added and removed only with its record in the account's feed: an `account.changed` event, `webhook.subscribed` or `webhook.deleted`, decided by the owner and signed by the owner key's request key over the webhook's value, `sha256=` and the SHA-256 of the address exactly as sent, then ` kinds=` and the kinds sorted and joined with commas, or `all`. The record never holds the address, which can carry a token, so Verdifax, which never holds the owner's request key, cannot add a destination for the account's events. The server refuses an address not sent in the form it stores, with a 400 naming that form.
- `CreateWebhook` now takes `opts *OwnerChangeOptions` after `types`, and `DeleteWebhook` now takes `opts` and returns `(*WebhookDeletion, error)`: both sign the change with the client's `SigningKey`, the owner key's request key, and return `ErrSigningKeyRequired` before anything is sent without one. The account's label is read from `GetAccount` unless `opts` names it. `DeleteWebhook` reads the subscription from `ListWebhooks` and signs its value; an ID the account holds no live webhook with is refused before the removal is sent. Both check the record in the answer, `CreatedWebhook.AccountChange` and `WebhookDeletion.AccountChange`: it must carry the change, the value, the owner as decider and the signature sent, or they return an error. These two signatures change; a caller passes `nil` for `opts` and reads the deletion's record.
- `WebhookValue(url, types)`, `WebhookSubscribed` and `WebhookDeleted` name the value and the changes; `WebhookValue` makes no request. The shared vector `sdk-webhook-change-vector.json` fixes the value for the four SDKs, the server and the verifier, and a test here reads it.
- The owner-replacement setting's description now says that, from verifier v0.35.0's server release on, Verdifax also cannot clear the owner key's request key while the owner blocks owner-key replacement.
- The user agent is `verdifax-sdk-go/1.16.0`.

## 1.15.0

The feed's head, and request-key changes read from the feed.

- A feed page that reaches the feed's end carries the feed's head: `SignalPage.Head`, a `FeedHead` (`verdifax.feed-head.v1`) with the account, the feed's highest event (`Sequence`) and its hash (`HeadHash`), `StatedAt`, `HeadStatementHash` and the public-log `Anchor`. It is Verdifax's statement of the feed's end, anchored on the public log as its own entry. It is not an event, and a page without one reads as before. A saved page keeps the head's exact bytes, as it keeps each event's.
- `FollowSignals` never passes the head to the handler. It keeps a head only when its sequence is the page's `next_after` and its `head_hash` is the event hash of the last event the handler finished in this call, after the handler has finished every event on that page. It passes each newer head to the new `FollowSignalsOptions.OnHead`, once per statement, a fresh statement for the same event included, and returns the one kept in the new `FollowSignalsError.Head`. Before the handler finishes an event in the call, the new `FollowSignalsOptions.AfterEventHash`, the event hash of event `after` as the caller saved it, stands for that event, so a follower resuming at the feed's end keeps the head it is served; without it, no head is kept until the handler finishes an event. An `AfterEventHash` that is not 64 lowercase hex characters is refused before sending. The four SDKs share this rule through `testdata/sdk-feed-head-vector.json`.
- Since v0.34.0, `verdifax-verify --signals` checks a saved feed against its head, fails a feed that ends below it, reports the feed complete as of the head's time on the log, and fails a head older than `--feed-head-max-age`, 24 hours by default.
- Every registration, rotation and holder's clear of a request key on a key in an account is now an `account.changed` event. `AccountChangeRequestKeyRegistered` (`request_key.registered`), `AccountChangeRequestKeyRotated` (`request_key.rotated`) and `AccountChangeRequestKeyCleared` (`request_key.cleared`) name the actions. A registration's and a rotation's `Value` is the new public key, and a clear's is empty. `AccountChange` gains `RequestKeyApproval`: on a rotation, and on a clear by the key's holder, the previous request key and its signature over the same bytes `RotateRequestKey` and `ClearRequestKey` sign. Verdifax's clear carries none.
- `RotateAccountRequestKey(ctx, newKey)` (owner key) replaces the owner key's request key with `POST /account/request-key`, as `RotateRequestKey` does for a key's own: the new key's proof and the current key's approval, the client signing with the new key only after the server accepts it, and keeping the current key after any error. The server seals the rotation in the account's feed with that approval, so the owner key's request-key chain continues.
- `FollowSignalsError` gains `AfterEventHash`, the event hash of event `After`: the last event the handler finished, or the `AfterEventHash` given when it finished none, and empty when neither. Resume with both.
- `RegisterRequestKey`, `RotateRequestKey`, `ClearRequestKey`, `RegisterAccountRequestKey`, `RotateAccountRequestKey` and `ClearAccountRequestKey` return the server's HTTP 409, "the request key changed since this change was signed", as an `*APIError` with the server's message, without a retry, and the client keeps its signing key.
- `PendingSignOffs` and `FollowSignals` read a feed holding the new account changes and heads as before, and a test holds them to it.
- `PendingSignOffs` now refuses a `run.sealed` event whose entry names no run, a null entry included, instead of skipping it: the server serves every `run.sealed` event with its own entry, even after the run is deleted. A run is still left out once its `run.deleted` event appears.
- `SignalData` gains `Deleted`, a `RunDeletion`: an event whose entry is a record since deleted, such as a refused, halted or failed run's receipt, is served with a null `Entry` and the record's tombstone in its place, and the SDK now reads it. An event that is its own sealed record, such as `run.sealed`, keeps its own entry. `RunDeletion` gains `LogEntries`, the deleted record's public-log entries as decimal entry numbers in ascending order, and `JobLinks`, a `DeletedJobLinks` with a deleted job step's own links (`PreviousRecordHashes`, `ExternalPrevious` and `Final`), present, even when empty, on a step deleted since the server release that came with verdifax-verify v0.34.0. Both keep the exact bytes the server sent.
- The user agent is `verdifax-sdk-go/1.15.0`.

## 1.14.0

The owner's blocks on Verdifax, deleted records, and execute bodies read strictly.

- `SetAccountSetting(ctx, setting, value, opts)` (owner key) sets one of the owner's two blocks with `PUT /account/settings/{setting}`: `AccountSettingOwnerReplacement` (`owner-replacement`), which stops Verdifax replacing or revoking the owner key, and `AccountSettingVerdifaxDeletion` (`verdifax-deletion`), which stops Verdifax deleting a record. The value is `SettingAllowed` or `SettingBlocked`. It returns the change sealed in the account's feed, an `AccountChange`, or nil when the value was already set.
- `DeleteRun(ctx, runID, recordHash, opts)` (owner key) deletes one of the account's records with `POST /account/runs/{id}/delete` and returns its tombstone, a `RunDeletion` sealed in the feed. `recordHash` is the record you mean to delete: a completed run's record hash, or a stopped run's receipt hash.
- Both are signed by the client's `SigningKey`, the owner key's request key. Verdifax never holds the owner's request key, so it cannot make a signature with it, and `verdifax-verify --signals --owner-request-key` confirms every owner change in the feed was signed with the owner's key. A client without one gets `ErrSigningKeyRequired` before anything is sent, and a bad setting, value, run number or hash is refused before sending too. The account number signed over is read with `GET /account` unless `OwnerChangeOptions.AccountID` gives it. `OwnerChangePreimage` returns the exact bytes signed, and makes no request. As `SignOff` does, each checks that the answer seals what it signed: the change's action, value and decider, or the tombstone's run, record hash and decider, and an owner signature with the signature, time and nonce sent and the signing key's public key. `SetAccountSetting` also accepts an `account_change` of null, when the value was already set, but refuses an answer with no `account_change`. Any other answer is an error.
- `AdminDeleteRun(ctx, runID)` and `AdminReplaceOwnerKey(ctx, accountID)` (admin key) are Verdifax deleting a record and starting the replacement of a lost owner key, each sealed in the account's feed as Verdifax's decision and refused with a 409 `*APIError` while the owner blocks it. `AdminReplaceOwnerKey` emails a one-time link to the address on file and returns neither the link nor a key.
- `Account` gains `OwnerReplacement` and `VerdifaxDeletion`, each `allowed` or `blocked`.
- The signal feed carries two new kinds, `SignalAccountChanged` (`account.changed`) and `SignalRunDeleted` (`run.deleted`), and a key change may be `verdifax.key-change.v2`, which seals who decided it in `decided_by`. `verdifax-verify --signals` reads them since v0.33.0. Webhook verification is unchanged.
- `PendingSignOffs(events)` leaves out a run whose `run.deleted` event is anywhere in the events given: a deleted record has nothing left to sign off. A `run.deleted` entry that cannot be read, or names no run, is an error.
- The server now refuses a field it does not define in a `/execute`, `/execute/batch` or `/execute/verify-determinism` body, signed text included, with a 400 `*APIError` that names it. The SDK sends only fields the server defines, and a test holds every body it builds to that list. A key you put in `AttestedContext` or one of the four caller blocks must be one the server defines.
- The user agent is `verdifax-sdk-go/1.14.0`.

## 1.13.0

Sign-off read as the verifier reads it, and the sign-off history's head statement.

- `PendingSignOffs(events)` reads the decision in force as `verdifax-verify` does: the latest job sign-off on a run governs when there is one, and otherwise the latest record sign-off. A run approved by a sign-off on its whole job is no longer listed, and one whose job was rejected is, even when the step carries its own approval.
- `PublicDecision` gains `SignedAs`, `Sequence`, `SignedAt` and `OwnDecision`: the kind of sign-off in force, its place and time, and, when the job's decision governs, the result's own latest decision. `DecisionInForce` is nil for a step whose job's sign-offs could not be read.
- `GetSignOffHistory` returns a list that ends with the chain's head statement, `verdifax.signoff-head.v1`, anchored on the public log. `verdifax-verify --signoff-history` reports the history complete as of that entry's time, and requires the head when a rule requires a person's sign-off, since v0.31.0. Decode only the `verdifax.signoff.v1` items into `SignOff`.
- The server now refuses a request that gives a query value more than once with an `*APIError` (400). The SDK gives each value once.
- The user agent is `verdifax-sdk-go/1.13.0`.

## 1.12.0

Data-quality declarations, pending sign-offs, public sign-offs, and requests read strictly.

- `PolicyContext` takes `DataQuality`: where the data came from (`Source`), the time it describes (`AsOf`, read as strictly as the server reads it) and the checks you ran on it (`Checks`, each a `DataCheck` with a `Name` and a `Result` of `pass`, `fail` or `warn`). It is sealed with the other policy values, and a policy's `data_quality` condition can require and test it. Verdifax judges none of it. The SDK checks it before sending, with the shared data-quality vector every SDK and the server test.
- `PendingSignOffs(events)` lists, in feed order, the runs whose allowing rule requires a person's sign-off and on which no approval is in force. It makes no request.
- `GetPublicSignOff(ctx, id)` and `GetPublicSignOffByToken(ctx, token)` read the sign-off a published run's audit report prints, and for a step of a job, the job's decision in force (`PublicSignOffAnswer`). No API key needed.
- `DownloadAuditPDFWithOptions` and `DownloadPublicAuditPDFWithOptions` take `AuditPDFOptions{AiOutputText, Fallback}`. The server now refuses a report format it does not know with a 400 `*APIError`; `Fallback: FallbackComprehensive` asks for the comprehensive report instead. `DownloadAuditPDF` now returns the server's reason for a refusal.
- `ListRunsParams`, `SearchRunsParams` and `ListAttestationsParams` take `Lenient`. The server now refuses a value it cannot read, such as a date in `SearchRuns`, with a 400 `*APIError`; `Lenient` asks it to ignore or replace the value instead.
- The user agent is `verdifax-sdk-go/1.12.0`.

## 1.11.0

Interrupted sign-offs and policy changes, exact records, and time limits.

- The signal feed carries a new kind, `SignalChainInterrupted` (`chain.interrupted`): a sign-off or policy change whose public-log entry was never confirmed has its place closed by a sealed, anchored record naming the entry it would have made. `verdifax-verify --signals`, `--signoff-history` and `--policy-history` accept a skipped place through one since v0.29.0. Sign-offs, policy changes and feed events keep marshaling as the exact bytes the server sent, numbers above 2^53 included.
- Every CI job has its own time limit.
- The user agent is `verdifax-sdk-go/1.11.0`.

## 1.10.0

Successful runs in the feed, restore gaps, a required AI review, reports that print the AI's answer, and the account's time zone.

- The signal feed carries two new kinds, `SignalRunSealed` (`run.sealed`), a successful run's record naming the run and the exact record it sealed, and `SignalChainGap` (`chain.gap`), a restore gap that names the places a chain skips after a restore from backup. `verdifax-verify --signals` reads both since v0.28.0.
- The policy test request takes `AIOutputDeclared` to test a policy whose `ai_review` sets `"required": true`: the server refuses, with reason `ai_review_required`, a step under the requirement that declares no AI output.
- `DownloadAuditPDFWithAnswer` sends the AI's exact answer, and the report prints it on its first page, marked as supplied, only when its SHA-256 is the hash the record seals; other text returns a 422 `*APIError`. `DownloadPublicAuditPDF` reads a published record's audit PDF with no key, with or without the answer.
- `SetAccountTimeZone` (owner key) sets the second time zone the account's audit PDFs show beside UTC: an IANA zone, `"none"` for UTC alone, or `""` for the server region's zone. `Account.TimeZone` reads it.
- The user agent is `verdifax-sdk-go/1.10.0`.

## 1.9.0

The AI review says what it found, and the trace that proves it comes back to you.

- When an account's AI review runs on a step's AI output, the record seals what it found: the review setup (prompt and model), the SHA-256 of the trace it checked, the checker, what the account policy chose a contradiction finding does (`halt` or `record`), the outcome (`clean`, `halted` or `recorded`) and the finding (two trace nodes and the opposing terms). Verdifax returns the trace once and does not store it; keep it to re-run the check with `verdifax-verify --aivp-trace` (or `--aivp-traces` for a job), since v0.27.0.
- `ExecuteResponse.AivpTraceText` and `ExecuteBatchResultRow.AivpTraceText` hold the trace of a released run; `APIError.AivpTraceText` holds it for a run the review halted. `ExecutionManifest.AivpReview` (`AivpReview`, `AivpFinding`) is the sealed review.
- The user agent is `verdifax-sdk-go/1.9.0`.

## 1.8.0

A publication says who decided.

- A run publication is now `verdifax.run-publication.v2` and seals who decided: `owner`, the account's owner key, or `verdifax_admin`, a Verdifax admin key, which can withdraw any public record and publish only records it made itself. Every change to a record's public state, Verdifax's included, is now sealed in the feed of the record's account. `RunPublication.DecidedBy` carries it, with the constants `PublicationByOwner` and `PublicationByVerdifax`. Publications sealed before v2 are v1, carry no `decided_by`, and were the owner's. `verdifax-verify --signals` reads v2 since v0.26.0.
- The user agent is `verdifax-sdk-go/1.8.0`.

## 1.7.0

- A published stopped run is served as its sealed receipt. `PublicationResult` has `PublicReceiptURL`, the address of a stopped run's receipt while it is public, `/public/runs/{token}/receipt.json`; a stopped run has no bundle address, so `PublicBundleURL` is empty for it. `verdifax-verify` checks the receipt address as it checks a saved receipt.
- `GetPublicReceiptByToken(ctx, token)` reads a published stopped run's sealed receipt from `GET /public/runs/{token}/receipt.json`, as the exact bytes the server sent, with no key.
- The user agent is `verdifax-sdk-go/1.7.0`.

## 1.6.0

- The account owner publishes the account's records. `PublishRun(ctx, runID)` makes a record made by any key of the account public on its random link with `POST /account/runs/{id}/publish`, and `UnpublishRun` withdraws it with `/unpublish`, keeping the link for a later publish. Both need the owner key and answer a `PublicationResult`: the run's public state, its links while public, and the `RunPublication` the call sealed (nil when the run was already in the asked state). A publication, `verdifax.run-publication.v1`, names the run, its record hash, its job and step and the time, with its place in the account's signal feed, and marshals as the exact bytes the server sent. The service's admin key cannot publish another key's record.
- Signal kinds `run.published` and `run.unpublished` (`SignalRunPublished`, `SignalRunUnpublished`); `verdifax-verify --signals` reads them since v0.24.0.
- The user agent is `verdifax-sdk-go/1.6.0`.

## 1.5.1

- A sign-off, a policy change and a feed event now marshal as the exact JSON bytes the server sent. Since server e233482 (November 8, 2026 UTC) a sign-off and an account policy change seal their place in the account's signal feed in their hash; 1.5.0 decoded them into types without that field, so a sign-off list saved with `json.Marshal` dropped it, and `verdifax-verify --signoff` reported a hash that does not recompute. No field the server seals is dropped now, including one a later server adds, and no large number is rounded. A record built in code marshals from its fields as before.
- `SignOff` and `PolicyActivation` have `Signal`, the record's place in the account's signal feed, a `*SignalLink`, nil on a record from before the feed and on a key's policy change.
- New type: `SignalLink`.
- The user agent is `verdifax-sdk-go/1.5.1`.

## 1.5.0

The signal feed. Every control signal Verdifax recorded for the account is one event in the account's feed, in order, each with its sealed entry: a refused, halted or failed run, a policy change, a sign-off, an approver key registered or revoked, and a member or feed key created or revoked. Each event's place and the previous event's hash are sealed inside its entry before that entry is anchored on the public log.

- New methods that read the feed: `GetSignals` reads one page after a place, and `FollowSignals` reads page after page from a place and calls a handler with each event until the handler returns an error or the context ends. A feed key reads `GET /signals`; with `AsOwner` the owner key reads `GET /account/signals`. Both refuse a negative `After`, a `Limit` outside 1 to 500, and a `Wait` that is not a whole number of seconds from 0 to 25, before sending anything. The HTTP timeout of a feed read is at least its wait plus 30 seconds, whatever the client's own timeout.
- `FollowSignals` reads each page from the page before's `next_after`, waits 25 seconds by default when there is no new event, and retries a failed read with the client's retry policy. It refuses a page that would make it skip or repeat an event. It stops with a `*FollowSignalsError` whose `After` is the last sequence the handler finished, so following again from there loses nothing. A handler returns `ErrStopFollowing` to stop without an error.
- New owner key methods for feed keys: `CreateFeedKey` and `RevokeFeedKey`. A feed key reads the signal feed and nothing else. `CreateFeedKey` refuses an empty name or one over 200 bytes before sending.
- New owner key methods for webhooks: `CreateWebhook`, `ListWebhooks`, `DeleteWebhook` and `ListWebhookDeliveries`. `CreateWebhook` refuses an address that does not start with `https://`, and a type that is not one of the nine kinds or is named twice, before sending anything; the server checks the address too. Its secret is shown once. A delivery is a copy: the pull feed and the public log are the record, and a missed delivery is read again from the feed.
- `GetFailureReceipt` returns the sealed failure receipt of a run that failed with a server error, as the exact JSON bytes the server sent. A failed run from before failure receipts comes back as a `*NotFoundError`.
- New functions that make no request: `VerifyWebhook` checks a delivery under the Standard Webhooks scheme (the `whsec_` secret, a `webhook-timestamp` within 5 minutes of now by default, and any `v1` signature in `webhook-signature`, compared in constant time over `webhook-id`, the timestamp and the raw body) and returns its event. Its error says which check failed and never holds the secret. `SignalEventHash` returns an event's hash.
- New types: `SignalEvent`, `SignalData`, `SignalPage`, `GetSignalsOptions`, `FollowSignalsOptions`, `FollowSignalsError`, `CreateFeedKeyResponse`, `Webhook`, `CreatedWebhook` and `WebhookDelivery`; the constant `DefaultWebhookTolerance`; the error `ErrStopFollowing`; and a constant for each of the nine kinds, `SignalRunRefused`, `SignalRunHalted`, `SignalRunFailed`, `SignalPolicyChanged`, `SignalSignOffRecorded`, `SignalApproverRegistered`, `SignalApproverRevoked`, `SignalKeyCreated` and `SignalKeyRevoked`.
- `SignalData.Entry` keeps the sealed entry as the exact JSON bytes the server sent.
- The user agent is `verdifax-sdk-go/1.5.0`.

The feed shows the signals Verdifax recorded for the account, in order. It cannot show a signal Verdifax never recorded. `verdifax-verify --signals` checks a saved feed.

## 1.4.0

Customer sign-off. An approver signs a decision, approve or reject, on one exact result: a completed run's record, a refused or halted run's receipt, or a whole job by its final step. Verdifax logs each sign-off on the public log, linked to the account's sign-off before it.

- New owner key methods: `RegisterApprover`, `ListApprovers`, `RevokeApprover` and `GetSignOffHistory`. `RegisterApprover` takes the approver's `SigningKey` and makes the proof on this machine, or takes the public key and proof that `ApproverKeyProof` made on the approver's machine and checks the proof before sending, so the owner never has to hold the approver's private key. No private key is sent. It refuses the client's own `SigningKey` as the approver key.
- New methods for a member key, or for the owner key with `AsOwner`: `SignOff`, `GetSignOffs` and `GetNewestSignOff`. `SignOff` reads the newest sign-off, hashes the note on this machine, signs with the approver key and submits. It sends the note's SHA-256, never its text; an empty note is no note, so no `note_hash` is sent. It returns an error if the returned record differs from what was signed in its signature, approver key, decision, previous sign-off hash or target. It refuses a bad target, decision or key before sending anything.
- New functions that make no request: `SignOffPreimage`, the bytes an approver key signs, and `ApproverKeyProof`, the registration proof.
- New types: `SignOff`, `SignOffTarget`, `SignOffOptions`, `RegisterApproverRequest`, `AccountRouteOptions`, `NewestSignOff`, `Approver` and `ApproverList`, and the constants `SignOffTargetRecord`, `SignOffTargetReceipt`, `SignOffTargetJob`, `SignOffApprove` and `SignOffReject`.
- `GetSignOffHistory` returns the exact JSON bytes the server sent, for `verdifax-verify --signoff-history`. `SignOff.Anchor` keeps the anchor's exact JSON bytes.
- `RunsExport` has `SignOffs`, the account's sign-offs, which the owner key's export carries, as the exact JSON bytes the server sent.
- The user agent is `verdifax-sdk-go/1.4.0`.

A record's digest is its `bundle_anchor.anchored_digest` from `GetRunArtifacts`, and a receipt's is its hash. An approver key is registered by the owner and is never a request key in the same account. A sign-off shows that the holder of a registered approver key signed that decision on that exact result, and that Verdifax logged it on the public log. It does not show the review was careful, the result was right, or who the person is: a key is not an identity. It gates nothing on its own. A later sign-off on the same result supersedes the earlier one, and nothing is deleted. Verdifax did not review the result. Since v0.22.0, verdifax-verify reads sign-offs.

## 1.3.0

Accounts. An account is a company, and every API key belongs to one account for life. The account's owner key manages the account and cannot run anything.

- New owner key methods: `GetAccount`, `CreateAccountKey`, `ListAccountKeys`, `RevokeAccountKey`, `RegisterAccountRequestKey`, `ClearAccountRequestKey`, `ListAccountRuns`, `ExportAccountRuns`, `ExportAccountRunsCSV`, `UploadAccountPolicy`, `ListAccountPolicies`, `GetAccountPolicy`, `TestAccountPolicy`, `GetAccountPolicyHistory` and `ActivateAccountPolicy`.
- New admin methods: `AdminCreateAccount` and `AdminListAccounts`.
- `AdminCreateKey` takes an optional `AdminCreateKeyOptions` whose `AccountID` puts a customer key in an existing account. Calls without it are unchanged. The response has `AccountID`.
- `ActivateAccountPolicy` signs every change over the account chain, `account-N`, with the policy activation preimage `ActivatePolicy` uses. Without a `SigningKey` it returns `ErrSigningKeyRequired` before sending, because the server refuses an unsigned change to an account policy.
- `RunsExport` has `AccountID`, `AccountPolicyDocuments` and `AccountPolicyHistory`, which the server sends on both exports, and `PolicyDocuments` and `PolicyHistory`, the exporting key's own, which the server already sent and earlier releases dropped. Both histories keep the exact JSON bytes.
- `ExportRow` and `RunSummary` have `APIKeyID`, the key that requested the run, on the key routes and the account routes. In the CSV export it is the last column, after `step_id`.
- New types: `Account`, `AccountKey`, `AccountKeyList`, `CreateAccountKeyRequest`, `CreateAccountKeyResponse`, `AdminCreateAccountRequest`, `AdminCreateAccountResponse` and `AdminCreateKeyOptions`.
- The user agent is `verdifax-sdk-go/1.3.0`.

The account number is a label Verdifax assigned, not a verified company identity. An account policy is the customer's own: Verdifax did not write, review or approve it. Every key in the account must pass the account policy on top of its own, and a run is admitted only when both allow. The account's view covers the runs its keys made through Verdifax, not runs made elsewhere.
- `DeterminismRun.Receipt` and `DeterminismDiff.Reason`: the server now compares two refused or halted replays by the manifest hashes they sealed, returns each sealed receipt, and says why there is no verdict when neither replay sealed a record.
