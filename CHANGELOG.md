# Changelog

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
