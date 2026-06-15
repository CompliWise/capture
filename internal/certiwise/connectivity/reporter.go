package connectivity

import (
	"log"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

// SubmitResult posts connectivity probe steps to the control plane.
func SubmitResult(client *certiwise.Client, steps []certiwise.ConnectivityTestStep) error {
	if err := client.SubmitConnectivityTest(steps); err != nil {
		return err
	}
	log.Printf("certiwise: connectivity test submitted (%d steps)", len(steps))
	return nil
}
