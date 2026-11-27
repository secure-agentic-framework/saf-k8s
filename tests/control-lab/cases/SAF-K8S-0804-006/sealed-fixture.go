package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const marker = "fixture public artifact marker"
const policy = "fixture-policy=v1"
const measurement = "fixture-approved"
const artifactID = "fixture-artifact-model-v1"
const recipient = "fixture-recipient-workload-v1"

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

func authenticationDenied(box cipher.AEAD, nonce, sealed, context []byte) bool {
	_, err := box.Open(nil, nonce, sealed, context)
	return err != nil
}

type contextRecord struct {
	Policy      string `json:"policy"`
	Measurement string `json:"measurement"`
	ArtifactID  string `json:"artifact_id"`
	ArtifactSHA string `json:"artifact_sha256"`
	Recipient   string `json:"recipient"`
}

func contextBytes(c contextRecord) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		panic("fixed context could not be encoded")
	}
	return b
}

func exercise() (map[string]any, error) {
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

	plainDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(marker)))
	approved := contextRecord{Policy: policy, Measurement: measurement, ArtifactID: artifactID,
		ArtifactSHA: plainDigest, Recipient: recipient}
	approvedContext := contextBytes(approved)
	baseline := box.Seal(nil, baselineNonce, []byte(marker), nil)
	sealed := box.Seal(nil, nonce, []byte(marker), approvedContext)
	encoded := base64.StdEncoding.EncodeToString(sealed)
	record, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "immutable": true,
		"metadata": map[string]string{"name": "fixture-sealed-artifact"},
		"data": map[string]string{"ciphertext": encoded, "context": string(approvedContext),
			"artifact_id": artifactID, "artifact_sha256": plainDigest, "recipient": recipient},
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
		Immutable *bool `json:"immutable"`
		Metadata  struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("fixture ConfigMap response is not JSON")
	}
	retrieved, err := base64.StdEncoding.DecodeString(stored.Data["ciphertext"])
	if err != nil || len(retrieved) == 0 {
		return nil, fmt.Errorf("fixture ciphertext unreadable")
	}
	if stored.Immutable == nil || !*stored.Immutable || stored.Metadata.Name != "fixture-sealed-artifact" ||
		stored.Metadata.Namespace != "saf-test" || stored.Data["context"] != string(approvedContext) ||
		stored.Data["artifact_id"] != artifactID || stored.Data["artifact_sha256"] != plainDigest ||
		stored.Data["recipient"] != recipient || !bytes.Equal(retrieved, sealed) || strings.Contains(string(raw), marker) {
		return nil, fmt.Errorf("stored record metadata, identity, or ciphertext did not match the fixed approved fixture")
	}
	opened, err := box.Open(nil, nonce, retrieved, approvedContext)
	if err != nil || string(opened) != marker || fmt.Sprintf("%x", sha256.Sum256(opened)) != plainDigest {
		return nil, fmt.Errorf("approved record did not open to the exact fixed plaintext digest")
	}
	tampered := bytes.Clone(retrieved)
	tampered[0] ^= 1
	wrongArtifactID := approved
	wrongArtifactID.ArtifactID = "fixture-artifact-model-v2"
	wrongArtifactDigest := approved
	wrongArtifactDigest.ArtifactSHA = fmt.Sprintf("%x", sha256.Sum256([]byte("different fixed public artifact marker")))
	wrongRecipient := approved
	wrongRecipient.Recipient = "fixture-recipient-workload-v2"
	wrongMeasurement := approved
	wrongMeasurement.Measurement = "fixture-other"
	wrongPolicy := approved
	wrongPolicy.Policy = "fixture-policy=v2"
	return map[string]any{
		"unbound_artifact_opened_without_identity": canOpen(box, baselineNonce, baseline, nil),
		"bound_artifact_requires_context":          authenticationDenied(box, nonce, retrieved, nil),
		"different_measurement_denied":             authenticationDenied(box, nonce, retrieved, contextBytes(wrongMeasurement)),
		"changed_policy_denied":                    authenticationDenied(box, nonce, retrieved, contextBytes(wrongPolicy)),
		"tampered_ciphertext_denied":               authenticationDenied(box, nonce, tampered, approvedContext),
		"approved_context_opened":                  true,
		"api_round_trip_retained_immutable_record": true,
		"artifact_identity_change_denied":          authenticationDenied(box, nonce, retrieved, contextBytes(wrongArtifactID)),
		"artifact_digest_change_denied":            authenticationDenied(box, nonce, retrieved, contextBytes(wrongArtifactDigest)),
		"recipient_change_denied":                  authenticationDenied(box, nonce, retrieved, contextBytes(wrongRecipient)),
		"record_identity": map[string]any{
			"name": stored.Metadata.Name, "namespace": stored.Metadata.Namespace,
			"immutable": *stored.Immutable, "artifact_id": stored.Data["artifact_id"],
			"artifact_sha256": stored.Data["artifact_sha256"], "recipient": stored.Data["recipient"],
			"plaintext_sha256_checked": plainDigest,
		},
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
