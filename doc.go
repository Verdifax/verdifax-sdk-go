// Package verdifax is the official Go SDK for the Verdifax
// orchestrator REST API.
//
// Verdifax converts any digital action into a cryptographically
// sealed, hardware-verified, and legally admissible fact. This
// SDK wraps the orchestrator's HTTP surface with Go idioms so
// applications can attest decisions, verify sealed manifests, and
// fetch audit artifacts without hand-rolling JSON marshalling.
//
// # Quickstart
//
//	import (
//	    "context"
//	    "fmt"
//	    "log"
//
//	    "github.com/Verdifax/verdifax-sdk-go"
//	)
//
//	func main() {
//	    client, err := verdifax.NewClient(verdifax.Config{
//	        BaseURL: "https://api.verdifax.com",
//	        APIKey:  os.Getenv("VERDIFAX_API_KEY"),
//	    })
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    run, err := client.Execute(context.Background(), &verdifax.ExecuteRequest{
//	        ProgramID:          "1111111111111111111111111111111111111111111111111111111111111111",
//	        RouteID:            "demo-attestation",
//	        RegistryRecordHash: "2222222222222222222222222222222222222222222222222222222222222222",
//	        PayloadText:        "first attestation",
//	    })
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    fmt.Printf("Sealed run %d, manifest hash %s\n", run.RunID, run.Manifest.ManifestHash)
//	}
//
// # Authentication
//
// Every authenticated endpoint expects the API key in the
// X-Verdifax-Key header. The Client injects it automatically when
// the Config carries APIKey.
//
// # Request signing
//
// Set Config.SigningKey to sign every path to POST /execute, each row
// of ExecuteBatch, and VerifyDeterminism with an Ed25519 private key
// held by the customer. GenerateRequestKey creates a key pair, and
// RegisterRequestKey, RotateRequestKey and ClearRequestKey manage the
// public key on the API key.
//
// # Jobs
//
// Client.Job returns a Job, whose Step method runs one step of a job
// and records its record hash, so a later step can name the steps it
// follows. A job map covers what was sent. It cannot show a step that
// was never sent.
//
// # Policies
//
// UploadPolicy stores the exact text of a customer's own policy,
// TestPolicy shows which rule would fire on sample inputs, and
// ActivatePolicy puts a stored document in force with a change record,
// signed by the SigningKey when the client has one. GetPolicyHistory
// returns the chain of changes for verdifax-verify --policy-history. A
// run declares what the rules read in PolicyContext. Verdifax did not
// write, review or approve a customer's policy. A pass means the rules
// ran, not that they are good rules.
//
// # Accounts
//
// An account is a company, and every API key belongs to one for life.
// The account's owner key manages it with GetAccount, CreateAccountKey,
// ListAccountKeys, RevokeAccountKey, RegisterAccountRequestKey,
// ClearAccountRequestKey, ListAccountRuns, ExportAccountRuns,
// ExportAccountRunsCSV, UploadAccountPolicy, ListAccountPolicies,
// GetAccountPolicy, TestAccountPolicy, GetAccountPolicyHistory and
// ActivateAccountPolicy, and cannot run anything itself. An admin
// creates accounts with AdminCreateAccount and lists them with
// AdminListAccounts. The account number is a label Verdifax assigned,
// not a verified company identity. An account policy is the customer's
// own, and Verdifax did not write, review or approve it. Every key in
// the account must pass it on top of its own policy, and a run is
// admitted only when both allow. The account's view covers the runs its
// keys made through Verdifax, not runs made elsewhere.
//
// # Sign-off
//
// A sign-off is an approver's decision, approve or reject, on one exact
// result: a record, a receipt, or a job by its final step. The owner key
// registers approver keys with RegisterApprover, lists them with
// ListApprovers and revokes them with RevokeApprover. SignOff reads the
// account's chain, hashes the note on this machine, signs with the
// approver key and submits; the note's text is never sent. GetSignOffs,
// GetNewestSignOff and GetSignOffHistory read them back. Set AsOwner to
// use the owner key's /account routes.
//
//	signOff, err := client.SignOff(ctx, verdifax.SignOffTarget{
//	    Kind:   verdifax.SignOffTargetRecord,
//	    RunID:  runID,
//	    Digest: anchoredDigest, // bundle_anchor.anchored_digest from GetRunArtifacts
//	}, verdifax.SignOffApprove, approverKey, &verdifax.SignOffOptions{Note: note})
//
// A record's digest is its bundle_anchor.anchored_digest from
// GetRunArtifacts, and a receipt's is its hash. An approver key is
// registered by the owner and is never a request key in the same
// account. A sign-off shows that the holder of a registered approver key
// signed that decision on that exact result, and that Verdifax logged it
// on the public log. It does not show the review was careful, the result
// was right, or who the person is: a key is not an identity. It gates
// nothing on its own. A later sign-off on the same result supersedes the
// earlier one, and nothing is deleted. Verdifax did not review the
// result. Since v0.22.0, verdifax-verify reads sign-offs.
//
// # Signal feed
//
// Every control signal Verdifax records for an account is one event in
// the account's feed, in order, each with its sealed entry. A feed key
// reads the feed with GetSignals and FollowSignals and does nothing
// else; with AsOwner the owner key reads it too. The owner key creates
// and revokes feed keys with CreateFeedKey and RevokeFeedKey, and
// manages webhooks with CreateWebhook, ListWebhooks, DeleteWebhook and
// ListWebhookDeliveries. VerifyWebhook checks a delivery's Standard
// Webhooks signature and returns its event, and SignalEventHash returns
// an event's hash. A delivery is a copy: the pull feed and the public
// log are the record. The feed cannot show a signal Verdifax never
// recorded. verdifax-verify --signals checks a saved feed.
//
//	err := feed.FollowSignals(ctx, lastSequenceRead, nil, func(event verdifax.SignalEvent) error {
//	    fmt.Println(event.Data.Sequence, event.Data.Kind)
//	    return nil
//	})
//
// # Error model
//
// Methods return one of three error kinds:
//
//   - *AuthError on missing/invalid API key (HTTP 401)
//   - *NotFoundError on missing resources (HTTP 404)
//   - *APIError on every other non-2xx response, with the
//     orchestrator's error message in .Message
//
// # Trust model
//
// The SDK only mediates HTTP I/O, it does NOT verify sealed
// manifests on its own. Use the verdifax-pepg-verify CLI (or its
// Go library form once published) for offline verification.
package verdifax
