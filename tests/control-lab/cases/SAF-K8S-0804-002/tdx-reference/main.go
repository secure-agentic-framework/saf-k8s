// Validate one public historical quote without exporting platform identifiers.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdx "github.com/google/go-tdx-guest/proto/tdx"
	fixture "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/testing/testdata"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/logger"
)

const (
	quoteDigest  = "6dde5548bec99147fef832643301f113df99931547be26df8ac376c4eaa5b5a7"
	reportDigest = "cb8e59049752c8d97d2d4d7ff4002dc266b96d3dd4e826011a2290984a49e117"
	mrTDDigest   = "d5f59dc8fcf53165b8871baf61bfa9b80fba55d7be012c4c8dd2e7ccd74ac995"
	tcbDenial    = "TDX TCB info reported by Intel PCS failed TCB status check: no matching TCB level found"
)

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func require(ok bool, check string) {
	if !ok {
		fmt.Fprintln(os.Stderr, "TDX reference failed:", check)
		os.Exit(1)
	}
}

func main() {
	logger.Init("tdx-reference", false, false, io.Discard)
	raw := testdata.RawQuote
	require(digest(raw) == quoteDigest, "published quote pin")
	historical := time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)
	expired := time.Date(2053, time.July, 1, 1, 0, 0, 0, time.UTC)

	require(verify.RawTdxQuote(raw, &verify.Options{Now: historical}) == nil, "historical signature and Intel PCK chain")
	err := verify.RawTdxQuote(raw, &verify.Options{Now: expired})
	require(err != nil && strings.Contains(err.Error(), "certificate has expired"), "expired Intel PCK chain")

	message, err := abi.QuoteToProto(raw)
	require(err == nil, "quote decoding")
	quote, ok := message.(*tdx.QuoteV4)
	require(ok, "quote version")
	body := quote.GetTdQuoteBody()
	require(digest(body.GetReportData()) == reportDigest && digest(body.GetMrTd()) == mrTDDigest,
		"expected REPORT_DATA and MR_TD hashes")

	wrongReport := &validate.Options{TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
		ReportData: make([]byte, abi.ReportDataSize),
	}}
	err = validate.TdxQuote(quote, wrongReport)
	require(err != nil && strings.Contains(err.Error(), "quote field REPORT_DATA"), "wrong expected REPORT_DATA")

	wrongMeasurement := &validate.Options{TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
		MrTd: make([]byte, abi.MrTdSize),
	}}
	err = validate.TdxQuote(quote, wrongMeasurement)
	require(err != nil && strings.Contains(err.Error(), "quote field MR_TD"), "wrong expected MR_TD")

	err = verify.RawTdxQuote(raw, &verify.Options{
		Now: historical, GetCollateral: true, CheckRevocations: true, Getter: fixture.TestGetter,
	})
	require(err != nil && err.Error() == tcbDenial, "historical signed collateral TCB denial")
	require(digest(raw) == quoteDigest, "exact same quote was used for every probe")

	row := map[string]any{
		"schema":                         "saf-intel-tdx-historical-reference-v1",
		"verifier":                       "google/go-tdx-guest@v0.3.1",
		"quote_sha256":                   quoteDigest,
		"historical_evaluation_time_utc": historical.Format(time.RFC3339),
		"expiry_probe_time_utc":          expired.Format(time.RFC3339),
		"historical_signature_and_pck_chain_verified": true,
		"pck_expiry_denied":                           true,
		"expected_report_and_measurement_matched":     true,
		"wrong_expected_report_data_denied":           true,
		"wrong_expected_measurement_denied":           true,
		"strict_archived_collateral_tcb_denied":       true,
		"quote_bytes_unchanged":                       true,
		"live_platform_or_freshness_observed":         false,
	}
	require(json.NewEncoder(os.Stdout).Encode(row) == nil, "normalized output")
}
