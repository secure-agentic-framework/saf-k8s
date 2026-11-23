package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const marker = "fixture public artifact marker"
const approved = "fixture-policy=v1;measurement=fixture-approved"

func kubectl(input []byte, args ...string) ([]byte, error) {
	base := []string{"--kubeconfig", os.Args[1], "--context", os.Args[2], "--namespace", "saf-test", "--request-timeout=10s"}
	cmd := exec.Command("kubectl", append(base, args...)...)
	cmd.Stdin = bytes.NewReader(input)
	return cmd.Output()
}

func canOpen(box cipher.AEAD, nonce, sealed, context []byte) bool {
	plaintext, err := box.Open(nil, nonce, sealed, context)
	return err == nil && string(plaintext) == marker
}

func exercise() (map[string]bool, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("fixture randomness unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	box, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, box.NonceSize())
	baselineNonce := make([]byte, box.NonceSize())
	for _, value := range [][]byte{nonce, baselineNonce} {
		if _, err := rand.Read(value); err != nil {
			return nil, fmt.Errorf("fixture randomness unavailable")
		}
	}

	baseline := box.Seal(nil, baselineNonce, []byte(marker), nil)
	sealed := box.Seal(nil, nonce, []byte(marker), []byte(approved))
	encoded := base64.StdEncoding.EncodeToString(sealed)
	record, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "immutable": true,
		"metadata": map[string]string{"name": "fixture-sealed-artifact"},
		"data":     map[string]string{"ciphertext": encoded, "context": approved},
	})
	if err != nil {
		return nil, err
	}
	if _, err := kubectl(record, "create", "-f", "-"); err != nil {
		return nil, fmt.Errorf("fixture ConfigMap creation failed")
	}
	raw, err := kubectl(nil, "get", "configmap", "fixture-sealed-artifact", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("fixture ConfigMap retrieval failed")
	}
	var stored struct {
		Immutable bool
		Data      map[string]string
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("fixture ConfigMap response is not JSON")
	}
	retrieved, err := base64.StdEncoding.DecodeString(stored.Data["ciphertext"])
	if err != nil || len(retrieved) == 0 {
		return nil, fmt.Errorf("fixture ciphertext unreadable")
	}
	tampered := bytes.Clone(retrieved)
	tampered[0] ^= 1
	return map[string]bool{
		"unbound_artifact_opened_without_identity": canOpen(box, baselineNonce, baseline, nil),
		"bound_artifact_requires_context":          !canOpen(box, nonce, retrieved, nil),
		"different_measurement_denied":             !canOpen(box, nonce, retrieved, []byte("fixture-policy=v1;measurement=fixture-other")),
		"changed_policy_denied":                    !canOpen(box, nonce, retrieved, []byte("fixture-policy=v2;measurement=fixture-approved")),
		"tampered_ciphertext_denied":               !canOpen(box, nonce, tampered, []byte(approved)),
		"approved_context_opened":                  canOpen(box, nonce, retrieved, []byte(approved)),
		"api_round_trip_retained_immutable_record": stored.Immutable && stored.Data["context"] == approved &&
			bytes.Equal(sealed, retrieved) && !strings.Contains(string(raw), marker),
	}, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: sealed-fixture kubeconfig context")
		os.Exit(2)
	}
	observed, err := exercise()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(observed); err != nil {
		os.Exit(1)
	}
}
