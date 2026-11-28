package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const nvidiaRootDigest = "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48"

// verifyGPU checks the archived H100 SPDM signature, its NVIDIA device chain,
// and the challenge bytes against the exact archived HCL bytes. The latter is
// only a fixture comparison; it does not claim a general CPU/GPU binding.
func verifyGPU(dir, rootPath string, when time.Time) (map[string]bool, error) {
	result := map[string]bool{
		"nvidia_spdm_signature_and_signer_verified": false,
		"gpu_capture_challenge_matches":             false,
		"gpu_challenge_matches_hcl_digest":          false,
	}

	read := func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(dir, name))
	}
	evidence, err := read(filepath.Join("gpu", "spdm-evidence.bin"))
	if err != nil {
		return result, fmt.Errorf("read SPDM evidence: %w", err)
	}
	chainBytes, err := read(filepath.Join("gpu", "gpu-cert-chain.pem"))
	if err != nil {
		return result, fmt.Errorf("read GPU certificate chain: %w", err)
	}
	challengeBytes, err := read(filepath.Join("gpu", "nonce.hex"))
	if err != nil {
		return result, fmt.Errorf("read GPU challenge: %w", err)
	}
	hcl, err := read(filepath.Join("cpu", "hcl.bin"))
	if err != nil {
		return result, fmt.Errorf("read HCL report: %w", err)
	}
	rootBytes, err := os.ReadFile(rootPath)
	if err != nil {
		return result, fmt.Errorf("read NVIDIA device root: %w", err)
	}

	rootBlock, rest := pem.Decode(rootBytes)
	if rootBlock == nil || rootBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return result, errors.New("invalid NVIDIA device root PEM")
	}
	rootDERHash := sha256.Sum256(rootBlock.Bytes)
	if hex.EncodeToString(rootDERHash[:]) != nvidiaRootDigest {
		return result, errors.New("NVIDIA device root DER pin mismatch")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return result, fmt.Errorf("parse NVIDIA device root: %w", err)
	}

	var certs []*x509.Certificate
	for rest := bytes.TrimSpace(chainBytes); len(rest) > 0; {
		block, trailing := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return result, errors.New("invalid GPU certificate chain PEM")
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return result, fmt.Errorf("parse GPU certificate: %w", parseErr)
		}
		certs = append(certs, cert)
		rest = bytes.TrimSpace(trailing)
	}
	if len(certs) != 5 || !bytes.Equal(certs[4].Raw, root.Raw) {
		return result, errors.New("unexpected archived GPU certificate chain")
	}
	leaf := certs[0]
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return result, errors.New("unexpected GPU device signing certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		if !bytes.Equal(cert.Raw, root.Raw) {
			intermediates.AddCert(cert)
		}
	}
	paths, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(paths) == 0 {
		return result, errors.New("GPU device certificate chain did not verify at archived time")
	}
	pathAnchored := false
	for _, path := range paths {
		if len(path) > 0 && bytes.Equal(path[len(path)-1].Raw, root.Raw) {
			pathAnchored = true
			break
		}
	}
	if !pathAnchored {
		return result, errors.New("GPU device certificate path did not terminate at pinned NVIDIA root")
	}

	// SPDM 1.1 measurement response layout: 37-byte request (including the
	// 32-byte challenge), then the response header. Signature is raw r||s
	// P-384 over every preceding byte, as in the archived NVIDIA transcript.
	const signatureLen = 96
	if len(evidence) < 37+8+signatureLen ||
		!bytes.Equal(evidence[:4], []byte{0x11, 0xe0, 0x01, 0xff}) || evidence[36] != 0 ||
		!bytes.Equal(evidence[37:41], []byte{0x11, 0x60, 0x00, 0x00}) {
		return result, errors.New("unexpected archived SPDM transcript shape")
	}
	cut := len(evidence) - signatureLen
	if cut < 37+8 {
		return result, errors.New("truncated SPDM signature payload")
	}
	hash := sha512.Sum384(evidence[:cut])
	r := new(big.Int).SetBytes(evidence[cut : cut+signatureLen/2])
	s := new(big.Int).SetBytes(evidence[cut+signatureLen/2:])
	if !ecdsa.Verify(key, hash[:], r, s) {
		return result, errors.New("GPU SPDM signature verification failed")
	}
	result["nvidia_spdm_signature_and_signer_verified"] = true

	challengeHex := strings.TrimSpace(string(challengeBytes))
	challenge, err := hex.DecodeString(challengeHex)
	if err != nil || len(challenge) != 32 {
		return result, errors.New("GPU challenge must be exactly 32 hex-encoded bytes")
	}
	// The challenge in the signed SPDM request occupies bytes 4..35.
	signedChallenge := evidence[4:36]
	result["gpu_capture_challenge_matches"] = bytes.Equal(signedChallenge, challenge)
	hclDigest := sha256.Sum256(hcl)
	result["gpu_challenge_matches_hcl_digest"] = bytes.Equal(signedChallenge, hclDigest[:])
	return result, nil
}
