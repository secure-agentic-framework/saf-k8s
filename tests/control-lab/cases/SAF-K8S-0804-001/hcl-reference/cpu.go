package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

const (
	hclReportOffset = 0x20
	hclReportLength = 1184
	hclClaimsOffset = 0x4d4
	hclClaimsLength = 1201
	maxHCLSize      = 16384
	maxClaimSize    = 8192
	maxCertificate  = 32768
	maxCRLSize      = 1 << 20
	archiveSize     = 2600
	archivePayload  = 2437
	archivePadding  = 163
)

// verifyCPU checks the archived Genoa SEV-SNP report and its HCL claim binding.
// The inputs are bounded to the public fixture's expected framing and are never
// included in errors or returned values.
func verifyCPU(dir, kdsChainPath string, when time.Time) (map[string]bool, error) {
	out := map[string]bool{
		"amd_snp_signature_and_signer_verified": false,
		"amd_archived_revocation_checked":       false,
		"hcl_runtime_claims_bound":              false,
		"secure_boot_enabled":                   false,
		"cpu_challenge_matches":                 false,
	}
	fail := func(stage string) (map[string]bool, error) { return out, fmt.Errorf("CPU reference: %s", stage) }
	if when.IsZero() {
		return fail("evaluation time required")
	}
	readBounded := func(path string, max int64) ([]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, errors.New("open failed")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.Size() <= 0 || st.Size() > max {
			return nil, errors.New("size rejected")
		}
		b, err := os.ReadFile(path)
		if err != nil || int64(len(b)) != st.Size() {
			return nil, errors.New("read failed")
		}
		return b, nil
	}
	cpuDir := filepath.Join(dir, "cpu")
	if st, statErr := os.Stat(cpuDir); statErr != nil || !st.IsDir() {
		// Also accept a caller that passes the CPU subdirectory itself.
		cpuDir = dir
	}
	read := func(name string, max int64) ([]byte, error) { return readBounded(filepath.Join(cpuDir, name), max) }

	hcl, err := read("hcl.bin", maxHCLSize)
	if err != nil || len(hcl) != archiveSize || binary.LittleEndian.Uint32(hcl[0:4]) != 1095517000 ||
		binary.LittleEndian.Uint32(hcl[4:8]) != 2 || binary.LittleEndian.Uint32(hcl[8:12]) != archivePayload ||
		binary.LittleEndian.Uint32(hcl[12:16]) != 2 || !bytes.Equal(hcl[16:32], make([]byte, 16)) {
		return fail("HCL framing rejected")
	}
	if binary.LittleEndian.Uint32(hcl[1216:1220]) != 1221 || binary.LittleEndian.Uint32(hcl[1220:1224]) != 1 ||
		binary.LittleEndian.Uint32(hcl[1224:1228]) != 2 || binary.LittleEndian.Uint32(hcl[1228:1232]) != 1 ||
		binary.LittleEndian.Uint32(hcl[1232:1236]) != hclClaimsLength ||
		!bytes.Equal(hcl[archivePayload:], make([]byte, archivePadding)) {
		return fail("runtime claims framing rejected")
	}
	report := hcl[hclReportOffset : hclReportOffset+hclReportLength]
	claimsBytes := hcl[hclClaimsOffset : hclClaimsOffset+hclClaimsLength]
	separateReport, err := read("snp-report.bin", hclReportLength)
	if err != nil || len(separateReport) != hclReportLength || !bytes.Equal(report, separateReport) {
		return fail("embedded report mismatch")
	}
	if err := abi.ValidateReportFormat(report); err != nil {
		return fail("SNP report format rejected")
	}

	// Require an exact AMD Genoa chain from the separately acquired KDS bundle,
	// and require the archive's individual ASK/ARK files to be those same certs.
	chainBytes, err := readBounded(kdsChainPath, maxCertificate*2)
	if err != nil {
		return fail("AMD trust chain unavailable")
	}
	root := trust.AMDRootCertsProduct("Genoa")
	if err := root.FromKDSCertBytes(chainBytes); err != nil || root.ProductCerts == nil || root.ProductCerts.Ask == nil || root.ProductCerts.Ark == nil {
		return fail("AMD trust chain rejected")
	}
	askPEM, err := read("certs/ask.pem", maxCertificate)
	if err != nil {
		return fail("archived ASK unavailable")
	}
	arkPEM, err := read("certs/ark.pem", maxCertificate)
	if err != nil {
		return fail("archived ARK unavailable")
	}
	archAsk, err1 := x509.ParseCertificate(pemCertificateBytes(askPEM))
	archArk, err2 := x509.ParseCertificate(pemCertificateBytes(arkPEM))
	if err1 != nil || err2 != nil || !bytes.Equal(archAsk.Raw, root.ProductCerts.Ask.Raw) || !bytes.Equal(archArk.Raw, root.ProductCerts.Ark.Raw) {
		return fail("AMD KDS root equality failed")
	}
	arkDigest := sha256.Sum256(root.ProductCerts.Ark.Raw)
	if hex.EncodeToString(arkDigest[:]) != "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1" {
		return fail("AMD ARK pin mismatch")
	}

	vcekDER, err := read("certs/vcek.der", maxCertificate)
	if err != nil {
		return fail("VCEK unavailable")
	}
	vcek, err := x509.ParseCertificate(vcekDER)
	if err != nil {
		return fail("VCEK rejected")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.ProductCerts.Ark)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(root.ProductCerts.Ask)
	if _, err := vcek.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fail("AMD certificate chain or validity rejected")
	}
	if err := verify.SnpReportSignature(report, vcek); err != nil {
		return fail("AMD SNP signature rejected")
	}
	protoReport, err := abi.ReportToProto(report)
	if err != nil {
		return fail("SNP report fields rejected")
	}
	signerInfo, err := abi.ParseSignerInfo(protoReport.GetSignerInfo())
	if err != nil || signerInfo.SigningKey != abi.VcekReportSigner {
		return fail("report signer is not AMD VCEK")
	}
	certExts, err := kds.CertificateExtensions(vcek, abi.VcekReportSigner)
	if err != nil || kds.TCBVersion(protoReport.GetReportedTcb()) != certExts.TCBVersion ||
		(!allZero(protoReport.GetChipId()) && !bytes.Equal(protoReport.GetChipId(), certExts.HWID)) {
		return fail("VCEK and reported TCB binding rejected")
	}
	out["amd_snp_signature_and_signer_verified"] = true

	crlBytes, err := read("certs/genoa-vcek.crl", maxCRLSize)
	if err != nil {
		return fail("archived revocation list unavailable")
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil || when.Before(crl.ThisUpdate) || when.After(crl.NextUpdate) || crl.CheckSignatureFrom(root.ProductCerts.Ark) != nil {
		return fail("archived revocation list invalid at evaluation time")
	}
	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(vcek.SerialNumber) == 0 || revoked.SerialNumber.Cmp(root.ProductCerts.Ask.SerialNumber) == 0 {
			return fail("signing certificate revoked at evaluation time")
		}
	}
	out["amd_archived_revocation_checked"] = true

	var claims map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(claimsBytes))
	dec.DisallowUnknownFields()
	if !json.Valid(claimsBytes) || dec.Decode(&claims) != nil {
		return fail("runtime claims JSON rejected")
	}
	claimDigest := sha256.Sum256(claimsBytes)
	if !bytes.Equal(report[0x50:0x70], claimDigest[:]) || !bytes.Equal(report[0x70:0x90], make([]byte, 32)) {
		return fail("runtime claim digest binding rejected")
	}
	out["hcl_runtime_claims_bound"] = true

	var vmConfig map[string]json.RawMessage
	if json.Unmarshal(claims["vm-configuration"], &vmConfig) != nil {
		return fail("runtime configuration claim rejected")
	}
	secureBootRaw := bytes.TrimSpace(vmConfig["secure-boot"])
	if !bytes.Equal(secureBootRaw, []byte("true")) && !bytes.Equal(secureBootRaw, []byte("false")) {
		return fail("Secure Boot claim rejected")
	}
	secureBoot := bytes.Equal(secureBootRaw, []byte("true"))
	out["secure_boot_enabled"] = secureBoot

	var userData string
	if json.Unmarshal(claims["user-data"], &userData) != nil || len(userData) != 128 || strings.Trim(userData, "0123456789abcdefABCDEF") != "" {
		return fail("user data claim rejected")
	}
	challengePath := filepath.Join(dir, "vtpm", "user.bin")
	if cpuDir == dir {
		challengePath = filepath.Join(dir, "..", "vtpm", "user.bin")
	}
	actualChallenge, err := readBounded(challengePath, 128)
	if err != nil || len(actualChallenge) != 64 {
		return fail("CPU challenge unavailable")
	}
	userDataBytes, err := hex.DecodeString(userData)
	if err != nil {
		return fail("user data encoding rejected")
	}
	out["cpu_challenge_matches"] = bytes.Equal(userDataBytes, actualChallenge)
	return out, nil
}

// pemCertificateBytes returns the first PEM certificate DER payload without
// exposing PEM or certificate contents in errors or logs.
func pemCertificateBytes(data []byte) []byte {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	return block.Bytes
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
