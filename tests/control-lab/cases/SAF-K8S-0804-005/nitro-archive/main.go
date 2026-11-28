package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	rootSHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
	maxDocSize = 1 << 20
	maxPayload = 1 << 16
)

var approvedPCRs = map[uint64]string{
	0: "c6ac6126521442b00689573ce1f62ab5951ed2fa4c7f68e75fed5f5fef5dba11",
	1: "647a94270b6dba6986f86667dbc6b77b7c58a9d5049a78156cfa49212a82429f",
	2: "545eeeed9a4a95fc187eaeddf169e12e464d93f17477ed047873e99f8b841ba4",
}

type coseEnvelope struct {
	protected   []byte
	unprotected cbor.RawMessage
	payload     []byte
	signature   []byte
}

type attestation struct {
	moduleID    string
	timestamp   uint64
	digest      string
	pcrs        map[uint64][]byte
	certificate []byte
	cabundle    [][]byte
	publicKey   []byte
	userData    []byte
	nonce       []byte
	nonceSet    bool
	keySet      bool
}

type sampleDecision struct {
	DocumentSHA256            string `json:"document_sha256"`
	TimestampMS               uint64 `json:"timestamp_ms"`
	AuthenticAtIssuance       bool   `json:"authentic_at_issuance"`
	ApprovedMeasurementsMatch bool   `json:"approved_measurements_match"`
	HasNonzeroPCR012          bool   `json:"has_nonzero_pcr0_through_pcr2"`
	NoncePresent              bool   `json:"nonce_present"`
	RequestedNonceMatches     bool   `json:"requested_nonce_matches"`
	RecipientKeyPresent       bool   `json:"recipient_key_present"`
	RecipientSatisfiesPolicy  bool   `json:"recipient_satisfies_policy"`
	LiveCertificateValid      bool   `json:"live_certificate_valid"`
	FreshTimestamp            bool   `json:"fresh_timestamp"`
	ReleaseAllowed            bool   `json:"release_allowed"`
}

type output struct {
	Schema          string                    `json:"schema"`
	AWSRootSHA256   string                    `json:"aws_root_sha256"`
	SampleDecisions map[string]sampleDecision `json:"sample_decisions"`
	BadSignature    bool                      `json:"bad_signature_rejected"`
	PayloadChange   bool                      `json:"payload_change_rejected_by_signature"`
}

func decoder() cbor.DecMode {
	m, err := (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  16,
		MaxArrayElements: 256,
		MaxMapPairs:      256,
	}).DecMode()
	if err != nil {
		panic("CBOR decoder configuration failed")
	}
	return m
}

func decodeCOSE(raw []byte) (coseEnvelope, error) {
	var result coseEnvelope
	if len(raw) == 0 || len(raw) > maxDocSize {
		return result, errors.New("size")
	}
	if raw[0]>>5 == 6 {
		var tag cbor.RawTag
		if err := cbor.Unmarshal(raw, &tag); err != nil || tag.Number != 18 {
			return result, errors.New("COSE_Sign1 tag")
		}
		raw = tag.Content
	}
	if err := decoder().Unmarshal(raw, &resultFields{out: &result}); err != nil {
		return result, fmt.Errorf("COSE_Sign1 structure: %w", err)
	}
	if len(result.protected) == 0 || len(result.unprotected) == 0 || len(result.payload) == 0 || len(result.signature) == 0 {
		return result, errors.New("empty")
	}
	if len(result.payload) > maxPayload || len(result.signature) != 96 {
		return result, errors.New("length")
	}
	if err := validateProtected(result.protected); err != nil {
		return result, err
	}
	if err := validateUnprotected(result.unprotected); err != nil {
		return result, err
	}
	return result, nil
}

// resultFields captures raw encodings so COSE verification uses the exact
// protected-header and payload bytes from the archive.
type resultFields struct{ out *coseEnvelope }

func (r *resultFields) UnmarshalCBOR(data []byte) error {
	var fields []cbor.RawMessage
	if err := decoder().Unmarshal(data, &fields); err != nil {
		return err
	}
	if len(fields) != 4 {
		return errors.New("array length")
	}
	if err := decoder().Unmarshal(fields[0], &r.out.protected); err != nil {
		return errors.New("protected bstr")
	}
	r.out.unprotected = fields[1]
	if err := decoder().Unmarshal(fields[2], &r.out.payload); err != nil {
		return errors.New("payload bstr")
	}
	if err := decoder().Unmarshal(fields[3], &r.out.signature); err != nil {
		return errors.New("signature bstr")
	}
	return nil
}

func validateProtected(raw []byte) error {
	var h map[int64]int64
	if err := decoder().Unmarshal(raw, &h); err != nil {
		return errors.New("protected header")
	}
	if len(h) != 1 || h[1] != -35 {
		return errors.New("algorithm")
	}
	return nil
}
func validateUnprotected(raw []byte) error {
	var h map[interface{}]interface{}
	if err := decoder().Unmarshal(raw, &h); err != nil || len(h) != 0 {
		return errors.New("unprotected header")
	}
	return nil
}

func parseAttestation(payload []byte) (attestation, error) {
	var a attestation
	if len(payload) == 0 || len(payload) > maxPayload {
		return a, errors.New("payload size")
	}
	var fields map[string]cbor.RawMessage
	if err := decoder().Unmarshal(payload, &fields); err != nil {
		return a, errors.New("payload map")
	}
	allowed := map[string]bool{"module_id": true, "timestamp": true, "digest": true, "pcrs": true, "certificate": true, "cabundle": true, "public_key": true, "user_data": true, "nonce": true}
	for k := range fields {
		if !allowed[k] {
			return a, errors.New("unknown field")
		}
	}
	for _, k := range []string{"module_id", "timestamp", "digest", "pcrs", "certificate", "cabundle"} {
		if _, ok := fields[k]; !ok {
			return a, errors.New("missing field")
		}
	}
	decode := func(name string, dst any) error { return decoder().Unmarshal(fields[name], dst) }
	if decode("module_id", &a.moduleID) != nil || a.moduleID == "" || len(a.moduleID) > 256 {
		return a, errors.New("module id")
	}
	if decode("timestamp", &a.timestamp) != nil || a.timestamp == 0 || a.timestamp > uint64(^uint64(0)>>1) {
		return a, errors.New("timestamp")
	}
	if decode("digest", &a.digest) != nil || a.digest != "SHA384" {
		return a, errors.New("digest")
	}
	if decode("pcrs", &a.pcrs) != nil || len(a.pcrs) != 16 {
		return a, errors.New("pcrs")
	}
	for i := uint64(0); i < 16; i++ {
		if len(a.pcrs[i]) != 48 {
			return a, errors.New("pcr size")
		}
	}
	if decode("certificate", &a.certificate) != nil || len(a.certificate) == 0 || len(a.certificate) > 1024 {
		return a, errors.New("certificate")
	}
	if decode("cabundle", &a.cabundle) != nil || len(a.cabundle) != 4 {
		return a, errors.New("cabundle")
	}
	for _, cert := range a.cabundle {
		if len(cert) == 0 || len(cert) > 1024 {
			return a, errors.New("cabundle cert")
		}
	}
	if raw, ok := fields["public_key"]; ok {
		a.keySet = true
		if decoder().Unmarshal(raw, &a.publicKey) != nil || len(a.publicKey) > 1024 {
			return a, errors.New("public key")
		}
	}
	if raw, ok := fields["user_data"]; ok {
		if decoder().Unmarshal(raw, &a.userData) != nil || len(a.userData) > 1024 {
			return a, errors.New("user data")
		}
	}
	if raw, ok := fields["nonce"]; ok {
		a.nonceSet = true
		if decoder().Unmarshal(raw, &a.nonce) != nil || len(a.nonce) > 1024 {
			return a, errors.New("nonce")
		}
	}
	return a, nil
}

func coseSigStructure(e coseEnvelope) []byte {
	// The array has the COSE Sig_structure tuple: context, protected bytes,
	// external_aad, and payload. Encoding it with definite-length CBOR preserves
	// the exact protected and payload byte strings inside the signed structure.
	encoded, err := cbor.Marshal([]any{"Signature1", []byte(e.protected), []byte{}, []byte(e.payload)})
	if err != nil {
		return nil
	}
	return encoded
}

func verifyCOSE(e coseEnvelope, a attestation) bool {
	leaf, err := x509.ParseCertificate(a.certificate)
	if err != nil {
		return false
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-384" {
		return false
	}
	structure := coseSigStructure(e)
	if structure == nil {
		return false
	}
	digest := sha512.Sum384(structure)
	r := new(big.Int).SetBytes(e.signature[:48])
	s := new(big.Int).SetBytes(e.signature[48:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

func pinnedRoot(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("root")
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("root pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("root cert")
	}
	h := sha256.Sum256(cert.Raw)
	if hex.EncodeToString(h[:]) != rootSHA256 {
		return nil, errors.New("root pin")
	}
	return cert, nil
}

func validatePath(a attestation, root *x509.Certificate, when time.Time) ([]*x509.Certificate, error) {
	if !bytes.Equal(a.cabundle[0], root.Raw) {
		return nil, errors.New("embedded root")
	}
	chainWant := make([]*x509.Certificate, 0, 5)
	leaf, err := x509.ParseCertificate(a.certificate)
	if err != nil {
		return nil, errors.New("leaf")
	}
	chainWant = append(chainWant, leaf)
	for i := len(a.cabundle) - 1; i >= 1; i-- {
		c, err := x509.ParseCertificate(a.cabundle[i])
		if err != nil {
			return nil, errors.New("intermediate")
		}
		chainWant = append(chainWant, c)
	}
	chainWant = append(chainWant, root)
	for _, cert := range chainWant {
		if when.Before(cert.NotBefore) || when.After(cert.NotAfter) {
			return nil, errors.New("certificate time")
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	for _, c := range chainWant[1 : len(chainWant)-1] {
		intermediates.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, errors.New("chain")
	}
	for _, chain := range chains {
		if len(chain) != len(chainWant) {
			continue
		}
		match := true
		for i := range chain {
			if !bytes.Equal(chain[i].Raw, chainWant[i].Raw) {
				match = false
				break
			}
		}
		if match {
			return chain, nil
		}
	}
	return nil, errors.New("chain shape")
}

func approvedMeasurements(a attestation) bool {
	for i, expected := range approvedPCRs {
		digest := sha256.Sum256(a.pcrs[i])
		if hex.EncodeToString(digest[:]) != expected {
			return false
		}
	}
	return true
}
func nonzeroPCR012(a attestation) bool {
	for i := uint64(0); i <= 2; i++ {
		if len(a.pcrs[i]) != 48 || bytes.Equal(a.pcrs[i], make([]byte, 48)) {
			return false
		}
	}
	return true
}

func recipientPolicy(a attestation, expectedSPKIDigest []byte) bool {
	if !a.keySet || len(a.publicKey) == 0 {
		return false
	}
	pubAny, err := x509.ParsePKIXPublicKey(a.publicKey)
	if err != nil {
		return false
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok || pub.N == nil || pub.N.BitLen() < 2048 || pub.E < 3 || pub.E%2 == 0 {
		return false
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false
	}
	sampleDigest := sha256.Sum256(spki)
	return bytes.Equal(expectedSPKIDigest, sampleDigest[:])
}

// Attestation decisions are intentionally fail-closed: these archives omit a
// nonce and recipient key, so they can never authorize a current release.
func decide(raw []byte, root *x509.Certificate, now time.Time, requestedNonce, expectedSPKIDigest []byte) sampleDecision {
	d := sampleDecision{DocumentSHA256: hexSHA256(raw)}
	e, err := decodeCOSE(raw)
	if err != nil {
		return d
	}
	a, err := parseAttestation(e.payload)
	if err != nil {
		return d
	}
	d.TimestampMS = a.timestamp
	d.HasNonzeroPCR012 = nonzeroPCR012(a)
	d.ApprovedMeasurementsMatch = approvedMeasurements(a)
	d.NoncePresent = a.nonceSet && len(a.nonce) > 0
	d.RequestedNonceMatches = d.NoncePresent && len(requestedNonce) > 0 && bytes.Equal(a.nonce, requestedNonce)
	d.RecipientKeyPresent = a.keySet && len(a.publicKey) > 0
	d.RecipientSatisfiesPolicy = recipientPolicy(a, expectedSPKIDigest)
	issued := time.UnixMilli(int64(a.timestamp))
	if _, err := validatePath(a, root, issued); err != nil {
		return d
	}
	d.AuthenticAtIssuance = verifyCOSE(e, a)
	if _, err := validatePath(a, root, now); err == nil {
		d.LiveCertificateValid = true
	}
	d.FreshTimestamp = !issued.After(now) && now.Sub(issued) <= 5*time.Minute
	d.ReleaseAllowed = d.AuthenticAtIssuance && d.ApprovedMeasurementsMatch && d.HasNonzeroPCR012 && d.NoncePresent && d.RequestedNonceMatches && d.RecipientKeyPresent && d.RecipientSatisfiesPolicy && d.LiveCertificateValid && d.FreshTimestamp
	return d
}

func hexSHA256(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func tamperSignatureRejected(raw []byte) bool {
	e, err := decodeCOSE(raw)
	if err != nil {
		return false
	}
	a, err := parseAttestation(e.payload)
	if err != nil {
		return false
	}
	if !verifyCOSE(e, a) {
		return false
	}
	e.signature = append([]byte(nil), e.signature...)
	e.signature[0] ^= 1
	return !verifyCOSE(e, a)
}

func tamperPayloadRejected(raw []byte) bool {
	e, err := decodeCOSE(raw)
	if err != nil {
		return false
	}
	a, err := parseAttestation(e.payload)
	if err != nil {
		return false
	}
	if !verifyCOSE(e, a) {
		return false
	}
	needle := a.pcrs[0]
	if len(needle) != 48 {
		return false
	}
	changed := append([]byte(nil), e.payload...)
	i := bytes.Index(changed, needle)
	if i < 0 {
		return false
	}
	changed[i] ^= 1
	e.payload = cbor.RawMessage(changed)
	changedAttestation, err := parseAttestation(changed)
	if err != nil {
		return false
	}
	return !verifyCOSE(e, changedAttestation)
}

func run() error {
	if len(os.Args) != 4 {
		return errors.New("usage")
	}
	root, err := pinnedRoot(os.Args[1])
	if err != nil {
		return errors.New("root validation failed")
	}
	debugRaw, err := os.ReadFile(os.Args[2])
	if err != nil {
		return errors.New("debug input unavailable")
	}
	measuredRaw, err := os.ReadFile(os.Args[3])
	if err != nil {
		return errors.New("measured input unavailable")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return errors.New("nonce generation failed")
	}
	fixtureRecipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.New("recipient policy setup failed")
	}
	fixtureSPKI, err := x509.MarshalPKIXPublicKey(&fixtureRecipient.PublicKey)
	if err != nil {
		return errors.New("recipient policy setup failed")
	}
	fixtureSPKIDigest := sha256.Sum256(fixtureSPKI)
	now := time.Now()
	out := output{Schema: "saf-nitro-archive-release-v1", AWSRootSHA256: rootSHA256,
		SampleDecisions: map[string]sampleDecision{
			"debug":    decide(debugRaw, root, now, nonce, fixtureSPKIDigest[:]),
			"measured": decide(measuredRaw, root, now, nonce, fixtureSPKIDigest[:]),
		},
		BadSignature:  tamperSignatureRejected(measuredRaw),
		PayloadChange: tamperPayloadRejected(measuredRaw),
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		return errors.New("output failed")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nitro archive validation failed:", err)
		os.Exit(2)
	}
}
