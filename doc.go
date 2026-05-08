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
//	    "github.com/Verdifax/verdifax-sdk-go/verdifax"
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
// The SDK only mediates HTTP I/O — it does NOT verify sealed
// manifests on its own. Use the verdifax-pepg-verify CLI (or its
// Go library form once published) for offline verification.
package verdifax
