// Check one historical Azure capture without exporting device identifiers.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func run() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("expected an archive directory and two independent vendor trust anchors")
	}
	capture := time.Unix(1791260867, 0).UTC()
	cpu, err := verifyCPU(os.Args[1], os.Args[2], capture)
	if err != nil {
		return fmt.Errorf("archived CPU verification: %w", err)
	}
	gpu, err := verifyGPU(os.Args[1], os.Args[3], capture)
	if err != nil {
		return fmt.Errorf("archived GPU verification: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema": "saf-azure-hcl-spdm-v1", "evaluation_time_utc": capture.Format(time.RFC3339),
		"cpu": cpu, "gpu": gpu, "live_assurance_observed": false,
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
