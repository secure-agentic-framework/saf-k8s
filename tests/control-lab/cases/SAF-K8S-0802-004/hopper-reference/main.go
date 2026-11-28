// Offline verifier for the exact NVIDIA Hopper SPDM 1.1 archive used by this case.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

//go:embed hopper-report.txt
var reportText string

//go:embed hopper-chain.pem
var chainPEM []byte

//go:embed nvidia-device-root.pem
var rootPEM []byte

const (
	requestLength    = 37
	signatureLength  = 96
	measurementStart = requestLength + 8
	digestNonce      = "e6b0f18e043f65a5921695f9305c42c26ef61de7dba7ca04e6dead18c8eb0e41"
	digestRecord     = "ccd646a0ba2f2fbdb91efaf5d666147b11f0012cc3021ef0d21dca00be8ede78"
	driverVersion    = "580.159.03"
	vbiosOpaque      = "0074009620000000"
)

type report struct {
	nonceSHA256        string
	measurementsSHA256 string
	measurements       int
	driver             string
	vbios              string
	values             map[int]string
}

func digest(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func decodeCertificates(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(bytes.TrimSpace(raw)) > 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("unexpected certificate carrier")
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("unparseable archived certificate")
		}
		out = append(out, cert)
		raw = rest
	}
	return out, nil
}

func parseReport(raw []byte) (report, error) {
	invalid := errors.New("unexpected archived Hopper SPDM transcript layout")
	if len(raw) < measurementStart+32+2+signatureLength ||
		!bytes.Equal(raw[:4], []byte{0x11, 0xe0, 0x01, 0xff}) || raw[36] != 0 ||
		!bytes.Equal(raw[37:41], []byte{0x11, 0x60, 0x00, 0x00}) {
		return report{}, invalid
	}
	response := raw[requestLength:]
	n := int(response[5]) | int(response[6])<<8 | int(response[7])<<16
	measurementEnd := measurementStart + n
	opaqueStart := measurementEnd + 32 + 2
	if n < 8 || opaqueStart > len(raw)-signatureLength ||
		opaqueStart+int(binary.LittleEndian.Uint16(raw[opaqueStart-2:opaqueStart])) != len(raw)-signatureLength {
		return report{}, invalid
	}
	measurements := raw[measurementStart:measurementEnd]
	var count int
	measurementValues := map[int]string{}
	for blocks := measurements; len(blocks) > 0; {
		if len(blocks) < 7 {
			return report{}, invalid
		}
		size := int(binary.LittleEndian.Uint16(blocks[2:4]))
		valueSize := int(binary.LittleEndian.Uint16(blocks[5:7]))
		if measurementValues[int(blocks[0])] != "" || blocks[1] != 1 || valueSize < 1 || size != valueSize+3 || size+4 > len(blocks) {
			return report{}, invalid
		}
		measurementValues[int(blocks[0])] = hex.EncodeToString(blocks[7 : size+4])
		count++
		blocks = blocks[size+4:]
	}
	if count != int(response[4]) {
		return report{}, invalid
	}
	out := report{nonceSHA256: digest(raw[4:36]), measurementsSHA256: digest(measurements), measurements: count, values: measurementValues}
	fields := map[uint16]bool{}
	for opaque := raw[opaqueStart : len(raw)-signatureLength]; len(opaque) > 0; {
		if len(opaque) < 4 {
			return report{}, invalid
		}
		field := binary.LittleEndian.Uint16(opaque[:2])
		n := int(binary.LittleEndian.Uint16(opaque[2:4]))
		if n+4 > len(opaque) || fields[field] {
			return report{}, invalid
		}
		fields[field] = true
		data := opaque[4 : n+4]
		switch field {
		case 3:
			out.driver = strings.TrimRight(string(data), "\x00")
		case 6:
			out.vbios = hex.EncodeToString(data)
		}
		opaque = opaque[n+4:]
	}
	if out.driver == "" || out.vbios == "" {
		return report{}, invalid
	}
	return out, nil
}

func verifySignature(raw []byte, key *ecdsa.PublicKey) bool {
	cut := len(raw) - signatureLength
	if cut < measurementStart {
		return false
	}
	hash := sha512.Sum384(raw[:cut])
	r := new(big.Int).SetBytes(raw[cut : cut+signatureLength/2])
	s := new(big.Int).SetBytes(raw[cut+signatureLength/2:])
	return ecdsa.Verify(key, hash[:], r, s)
}

func checkArchive() (map[string]any, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(reportText))
	if err != nil {
		return nil, errors.New("invalid archived transcript hex")
	}
	meta, err := parseReport(decoded)
	if err != nil {
		return nil, err
	}
	chain, err := decodeCertificates(chainPEM)
	if err != nil || len(chain) != 5 {
		return nil, errors.New("expected exact archived five-certificate chain")
	}
	anchors, err := decodeCertificates(rootPEM)
	if err != nil || len(anchors) != 1 || !bytes.Equal(anchors[0].Raw, chain[4].Raw) {
		return nil, errors.New("certificate chain does not end at the independently packaged root")
	}
	root := anchors[0]
	key, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() || chain[0].IsCA ||
		(chain[0].KeyUsage&x509.KeyUsageDigitalSignature) == 0 {
		return nil, errors.New("unexpected device attestation leaf key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	others := x509.NewCertPool()
	for _, cert := range chain[1:4] {
		others.AddCert(cert)
	}
	when := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	opts := x509.VerifyOptions{Roots: roots, Intermediates: others, CurrentTime: when,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	paths, err := chain[0].Verify(opts)
	if err != nil || len(paths) != 1 || len(paths[0]) != len(chain) ||
		!bytes.Equal(paths[0][len(chain)-1].Raw, root.Raw) || !verifySignature(decoded, key) {
		return nil, errors.New("archived device chain or SPDM signature was not verified")
	}
	anchored := meta.nonceSHA256 == digestNonce && meta.measurementsSHA256 == digestRecord &&
		meta.measurements == 64 && meta.driver == driverVersion && meta.vbios == vbiosOpaque
	if !anchored {
		return nil, errors.New("signed measurements or expected report bindings differ from the pinned archive")
	}
	noAnchor := opts
	noAnchor.Roots = x509.NewCertPool()
	noAnchor.Intermediates = others.Clone()
	noAnchor.Intermediates.AddCert(chain[4])
	_, rejectedRoot := chain[0].Verify(noAnchor)
	var authority x509.UnknownAuthorityError
	tooEarly := opts
	tooEarly.CurrentTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	_, rejectedTime := chain[0].Verify(tooEarly)
	var timing x509.CertificateInvalidError
	modified := append([]byte(nil), decoded...)
	modified[measurementStart+10] ^= 1
	return map[string]any{
		"schema":                                       "saf-nvidia-hopper-archived-spdm-v1",
		"transcript_sha256":                            digest(decoded),
		"device_root_sha256":                           digest(root.Raw),
		"reference_evaluation_at_utc":                  when.Format(time.RFC3339),
		"measurement_record_sha256":                    meta.measurementsSHA256,
		"measurement_count":                            meta.measurements,
		"driver_version":                               meta.driver,
		"archived_device_chain_and_signature_verified": true,
		"signed_report_fields_match_pinned_reference":  anchored,
		"changed_measurement_signature_denied":         !verifySignature(modified, key),
		"embedded_root_without_trust_denied":           errors.As(rejectedRoot, &authority),
		"pre_validity_chain_denied":                    errors.As(rejectedTime, &timing) && timing.Reason == x509.Expired,
		"measurement_values":                           meta.values,
		"live_device_or_freshness_observed":            false,
	}, nil
}

func main() {
	result, err := checkArchive()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(3)
	}
}
