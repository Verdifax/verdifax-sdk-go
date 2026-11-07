# Changelog

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
