package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdx "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
)

const (
	archivedQuoteSHA256     = "7cdbd00a3921dd18631d33f7ba2f5317057e3abe8ac14335005908c371060ff9"
	archivedUnpaddedSHA256  = "62fad0ba054a3a9244c0c517e67b14e1945ffafaca0e3d4a33326f07a322efbd"
	archivedQuoteSize       = 4935
	archivedQuotePaddedSize = 8000
	intelRootDERSHA256      = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
	archivedMRTDHex         = "f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3"
)

var (
	evaluationTime   = time.Date(2026, 10, 6, 4, 0, 0, 0, time.UTC)
	expiredProbeTime = time.Date(2026, 11, 15, 4, 0, 0, 0, time.UTC)
)

// archiveGetter implements the narrow HTTPSGetter surface expected by the
// pinned verifier. Every request is resolved from the supplied archive; an
// unknown URL is an error and can never fall through to the network.
type archiveGetter struct {
	directory          string
	omitPlatformCRL    bool
	requestedBasenames map[string]bool
}

func (g *archiveGetter) Get(endpoint string) (map[string][]string, []byte, error) {
	var artifact, headerName, chain string
	switch endpoint {
	case pcs.TcbInfoURL("00806f050000"), pcs.TcbInfoURL("00806F050000"):
		artifact, headerName, chain = "tcb-info.json", "Tcb-Info-Issuer-Chain", "tcb-info-chain.pem"
	case pcs.QeIdentityURL():
		artifact, headerName, chain = "qe-identity.json", "Sgx-Enclave-Identity-Issuer-Chain", "qe-identity-chain.pem"
	case pcs.PckCrlURL("platform"):
		if g.omitPlatformCRL {
			return nil, nil, fmt.Errorf("archived platform CRL deliberately unavailable")
		}
		artifact, headerName, chain = "pck-platform-crl.der", "Sgx-Pck-Crl-Issuer-Chain", "pck-sign-chain.pem"
	case "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der":
		artifact = "root-ca-crl.der"
	default:
		return nil, nil, fmt.Errorf("unexpected archived PCS lookup")
	}
	body, err := os.ReadFile(filepath.Join(g.directory, "collateral", artifact))
	if err != nil {
		return nil, nil, fmt.Errorf("read archived PCS artifact %s: %w", artifact, err)
	}
	if g.requestedBasenames != nil {
		g.requestedBasenames[artifact] = true
	}
	headers := make(map[string][]string)
	if chain != "" {
		pemBytes, err := os.ReadFile(filepath.Join(g.directory, "collateral", chain))
		if err != nil {
			return nil, nil, fmt.Errorf("read archived issuer chain %s: %w", chain, err)
		}
		headers[headerName] = []string{url.QueryEscape(string(pemBytes))}
	}
	return headers, body, nil
}

func hashHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func loadPinnedRoot(path string) (*x509.CertPool, string, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read Intel trust root: %w", err)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, "", errors.New("Intel trust root PEM is invalid")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse Intel trust root: %w", err)
	}
	rootHash := hashHex(root.Raw)
	if rootHash != intelRootDERSHA256 {
		return nil, "", errors.New("Intel trust root digest mismatch")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool, rootHash, nil
}

func requireBeforeEvaluation(label string, value time.Time) error {
	if value.IsZero() || value.After(evaluationTime) {
		return fmt.Errorf("%s is later than the archived evaluation time", label)
	}
	return nil
}

func verifySignedCollateralIssueTimes(directory string) error {
	for _, item := range []struct {
		file string
		key  string
	}{
		{"tcb-info.json", "tcbInfo"},
		{"qe-identity.json", "enclaveIdentity"},
	} {
		data, err := os.ReadFile(filepath.Join(directory, "collateral", item.file))
		if err != nil {
			return fmt.Errorf("read %s: %w", item.file, err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(data, &document); err != nil {
			return fmt.Errorf("parse %s: %w", item.file, err)
		}
		var signedBody struct {
			IssueDate time.Time `json:"issueDate"`
		}
		if err := json.Unmarshal(document[item.key], &signedBody); err != nil {
			return fmt.Errorf("parse signed contents of %s: %w", item.file, err)
		}
		if err := requireBeforeEvaluation(item.file+" issueDate", signedBody.IssueDate); err != nil {
			return err
		}
	}
	return nil
}

func verifyCRLTime(directory, name string) error {
	data, err := os.ReadFile(filepath.Join(directory, "collateral", name))
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	if err := requireBeforeEvaluation(name+" ThisUpdate", crl.ThisUpdate); err != nil {
		return err
	}
	if evaluationTime.After(crl.NextUpdate) {
		return fmt.Errorf("%s is expired at the archived evaluation time", name)
	}
	return nil
}

func requireCRLDenial(directory string, roots *x509.CertPool, quote []byte, now time.Time) error {
	getter := &archiveGetter{directory: directory, omitPlatformCRL: true}
	err := verify.RawTdxQuote(quote, &verify.Options{
		TrustedRoots: roots, Now: now, GetCollateral: true, CheckRevocations: true,
		Getter: getter,
	})
	if err == nil || !strings.HasPrefix(err.Error(), "unable to receive PCK CRL: archived platform CRL deliberately unavailable") {
		return errors.New("missing platform CRL did not cause an explicit revocation-check denial")
	}
	return nil
}

// signedCollateral verifies the archived quote and vendor collateral without
// network access. The input directory contains quote.bin, nonce.hex and a
// collateral subdirectory; rootFile is the separately pinned Intel root PEM.
func signedCollateral(directory, rootFile string) (map[string]any, error) {
	roots, rootHash, err := loadPinnedRoot(rootFile)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(directory, "quote.bin"))
	if err != nil {
		return nil, fmt.Errorf("read archived quote: %w", err)
	}
	if len(raw) != archivedQuotePaddedSize || hashHex(raw) != archivedQuoteSHA256 {
		return nil, errors.New("full archived quote digest mismatch")
	}
	quoteLength := 636 + int(binary.LittleEndian.Uint32(raw[632:636]))
	if quoteLength != archivedQuoteSize || quoteLength > len(raw) || hashHex(raw[:quoteLength]) != archivedUnpaddedSHA256 {
		return nil, errors.New("unpadded archived quote digest or length mismatch")
	}
	for _, b := range raw[quoteLength:] {
		if b != 0 {
			return nil, errors.New("archived quote has nonzero end padding")
		}
	}
	if binary.LittleEndian.Uint16(raw[:2]) != 4 {
		return nil, errors.New("archived quote is not TDX quote version 4")
	}

	nonceText, err := os.ReadFile(filepath.Join(directory, "nonce.hex"))
	if err != nil {
		return nil, fmt.Errorf("read archived nonce: %w", err)
	}
	nonce, err := hex.DecodeString(strings.TrimSpace(string(nonceText)))
	if err != nil || len(nonce) != 64 {
		return nil, errors.New("archived nonce is not a 64-byte hexadecimal value")
	}
	measurement, err := hex.DecodeString(archivedMRTDHex)
	if err != nil || len(measurement) != 48 {
		return nil, errors.New("internal archived measurement pin is invalid")
	}
	message, err := abi.QuoteToProto(raw[:quoteLength])
	if err != nil {
		return nil, fmt.Errorf("decode archived quote: %w", err)
	}
	quote, ok := message.(*tdx.QuoteV4)
	if !ok {
		return nil, errors.New("archived quote did not decode as TDX quote v4")
	}
	if err := validate.TdxQuote(quote, &validate.Options{TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
		ReportData: nonce, MrTd: measurement,
	}}); err != nil {
		return nil, fmt.Errorf("expected quote binding check failed: %w", err)
	}

	if err := verifySignedCollateralIssueTimes(directory); err != nil {
		return nil, err
	}
	if err := verifyCRLTime(directory, "pck-platform-crl.der"); err != nil {
		return nil, err
	}
	if err := verifyCRLTime(directory, "root-ca-crl.der"); err != nil {
		return nil, err
	}

	getter := &archiveGetter{directory: directory, requestedBasenames: make(map[string]bool)}
	if err := verify.RawTdxQuote(raw[:quoteLength], &verify.Options{
		TrustedRoots: roots, Now: evaluationTime, GetCollateral: true,
		CheckRevocations: true, Getter: getter,
	}); err != nil {
		return nil, fmt.Errorf("strict archived collateral and revocation verification failed: %w", err)
	}
	if err := requireCRLDenial(directory, roots, raw[:quoteLength], evaluationTime); err != nil {
		return nil, err
	}
	expiredErr := verify.RawTdxQuote(raw[:quoteLength], &verify.Options{
		TrustedRoots: roots, Now: expiredProbeTime, GetCollateral: true,
		CheckRevocations: true, Getter: &archiveGetter{directory: directory},
	})
	if expiredErr == nil || expiredErr.Error() != "could not verify collaterals obtained: tcbInfo has expired" {
		return nil, errors.New("expired collateral probe did not produce an explicit expiry denial")
	}

	used := make([]string, 0, len(getter.requestedBasenames))
	for basename := range getter.requestedBasenames {
		used = append(used, basename)
	}
	sort.Strings(used)
	want := []string{"pck-platform-crl.der", "qe-identity.json", "root-ca-crl.der", "tcb-info.json"}
	if !slices.Equal(used, want) {
		return nil, errors.New("strict verification did not use the four expected archived PCS artifacts")
	}

	return map[string]any{
		"quote_sha256":                               hashHex(raw),
		"evaluation_time_utc":                        evaluationTime.Format(time.RFC3339),
		"expired_probe_time_utc":                     expiredProbeTime.Format(time.RFC3339),
		"intel_root_sha256":                          rootHash,
		"strict_collateral_and_revocations_verified": true,
		"archived_report_data_and_mrtd_match":        true,
		"expired_collateral_rejected":                true,
		"missing_platform_crl_rejected":              true,
		"local_pcs_artifacts_used":                   used,
		"live_quote_or_current_collateral_observed":  false,
	}, nil
}
