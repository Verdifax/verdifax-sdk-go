# Changelog

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
