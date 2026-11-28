// cpu-reference is a harmless CPU workload for a Confidential Space VM.
// It computes a bounded hash chain, then uses a WIF-federated identity to
// read one inert Cloud Storage object. It never handles private input or keys.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const tokenFile = "/run/container_launcher/attestation_verifier_claims_token"

var buildVariant = "baseline"
var wifProjectNumber = ""
var wifPool = ""
var wifProvider = ""
var fixtureBucket = ""
var fixtureObject = ""
var fixtureSHA256 = ""
var resourceMode = "gcs"
var kmsKeyName = ""

type result struct {
	Schema              string `json:"schema"`
	Mode                string `json:"mode"`
	BuildVariant        string `json:"build_variant"`
	ExpectedAccess      bool   `json:"expected_access"`
	AccessDecision      string `json:"access_decision"`
	DenialStage         string `json:"denial_stage,omitempty"`
	DenialMarker        string `json:"denial_marker,omitempty"`
	DenialHTTP          int    `json:"denial_http_status,omitempty"`
	Rounds              uint64 `json:"cpu_rounds"`
	CPUWallMillis       int64  `json:"cpu_wall_ms"`
	OutputDigest        string `json:"output_digest"`
	InferenceExamples   uint64 `json:"inference_examples"`
	ClassZeroCount      uint64 `json:"class_zero_count"`
	FixtureDigest       string `json:"fixture_digest,omitempty"`
	FixtureMatched      bool   `json:"fixture_matched,omitempty"`
	TokenAgeSeconds     int64  `json:"token_age_seconds,omitempty"`
	TokenHWModel        string `json:"token_hwmodel,omitempty"`
	TokenNonceCount     int    `json:"token_nonce_count,omitempty"`
	TokenNonceMatch     bool   `json:"token_nonce_match"`
	TokenSummaryTrusted bool   `json:"token_summary_trusted"`
	StartedUTC          string `json:"started_utc"`
	FinishedUTC         string `json:"finished_utc"`
}

func main() {
	started := time.Now().UTC()
	mode := flag.String("mode", envOr("MODE", "probe"), "cpu-only or probe")
	flag.Parse()
	if err := run(started, *mode); err != nil {
		// Error messages are deliberately generic. Never print tokens, response
		// bodies, object contents, URLs with credentials, or environment values.
		fmt.Fprintln(os.Stderr, "workload failed:", err)
		os.Exit(1)
	}
}

func run(started time.Time, mode string) error {
	if mode != "cpu-only" && mode != "probe" {
		return errors.New("MODE must be cpu-only or probe")
	}
	rounds, err := boundedUintEnv("CPU_ROUNDS", 2_000_000, 1, 100_000_000)
	if err != nil {
		return err
	}
	expectAccess, err := boolEnv("EXPECT_ACCESS", true)
	if err != nil {
		return err
	}
	if buildVariant == "" || len(buildVariant) > 80 {
		return errors.New("invalid build variant")
	}
	negativeCase := strings.ToLower(strings.TrimSpace(os.Getenv("NEGATIVE_CASE")))
	if negativeCase != "" && negativeCase != "attribute_condition" && negativeCase != "invalid_signature" && negativeCase != "resource_forbidden" {
		return errors.New("NEGATIVE_CASE is invalid")
	}

	startedCPU := time.Now()
	digest, classZeroCount := runInference(rounds)
	cpuElapsed := time.Since(startedCPU)

	res := result{
		Schema:            "saf-cs-cpu-reference/v1",
		Mode:              mode,
		BuildVariant:      buildVariant,
		ExpectedAccess:    mode == "probe" && expectAccess,
		Rounds:            rounds,
		CPUWallMillis:     cpuElapsed.Milliseconds(),
		OutputDigest:      hex.EncodeToString(digest[:]),
		InferenceExamples: rounds,
		ClassZeroCount:    classZeroCount,
		StartedUTC:        started.Format(time.RFC3339Nano),
	}
	if mode == "cpu-only" {
		res.AccessDecision = "not_requested"
		return emit(res)
	}

	marker, stage, status, denialMarker, tokenInfo, fetchErr := readFixture(context.Background(), negativeCase)
	res.TokenAgeSeconds = tokenInfo.AgeSeconds
	res.TokenHWModel = tokenInfo.HWModel
	res.TokenNonceCount = tokenInfo.NonceCount
	res.TokenNonceMatch = tokenInfo.NonceMatch
	res.TokenSummaryTrusted = tokenInfo.Trusted
	if fetchErr != nil {
		if !expectAccess && isExpectedDenial(negativeCase, denialMarker, stage, status) {
			res.AccessDecision = "denied_as_expected"
			res.DenialStage = stage
			res.DenialMarker = denialMarker
			res.DenialHTTP = status
			return emit(res)
		}
		if isDenyStage(stage) {
			return fmt.Errorf("fixture access denied at %s (HTTP %d)", stage, status)
		}
		return fmt.Errorf("fixture access failed at %s (HTTP %d)", stage, status)
	}
	if !expectAccess {
		return errors.New("fixture access succeeded although denial was expected")
	}

	expected := strings.ToLower(strings.TrimSpace(fixtureSHA256))
	if expected == "" || len(expected) != sha256.Size*2 {
		return errors.New("FIXTURE_SHA256 must contain a SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return errors.New("FIXTURE_SHA256 is not valid hexadecimal")
	}
	actual := sha256.Sum256(marker)
	res.AccessDecision = "allowed"
	res.FixtureDigest = hex.EncodeToString(actual[:])
	res.FixtureMatched = res.FixtureDigest == expected
	if !res.FixtureMatched {
		return errors.New("fixture digest did not match the approved value")
	}
	return emit(res)
}

type tokenSummary struct {
	AgeSeconds int64
	HWModel    string
	NonceCount int
	NonceMatch bool
	Trusted    bool
}

func readFixture(ctx context.Context, negativeCase string) ([]byte, string, int, string, tokenSummary, error) {
	projectNumber := strings.TrimSpace(wifProjectNumber)
	pool := strings.TrimSpace(wifPool)
	provider := strings.TrimSpace(wifProvider)
	for _, value := range []string{projectNumber, pool, provider} {
		if value == "" {
			return nil, "configuration", 0, "", tokenSummary{}, errors.New("missing required workload configuration")
		}
	}
	var subjectToken []byte
	var err error
	nonce := strings.TrimSpace(os.Getenv("CHALLENGE_NONCE"))
	if nonce != "" {
		subjectToken, err = requestLauncherToken(ctx, envOr("CHALLENGE_AUDIENCE", "https://sts.googleapis.com/saf-reference"), nonce)
	} else {
		subjectToken, err = os.ReadFile(tokenFile)
	}
	if err != nil || len(bytes.TrimSpace(subjectToken)) == 0 {
		return nil, "attestation_token", 0, "", tokenSummary{}, errors.New("attestation token unavailable")
	}
	tokenInfo := summarizeToken(subjectToken, nonce)
	audience := fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectNumber, pool, provider)
	if negativeCase == "invalid_signature" {
		return compareTokenSignature(ctx, audience, subjectToken, tokenInfo)
	}
	accessToken, status, denyMarker, err := exchangeToken(ctx, audience, strings.TrimSpace(string(subjectToken)))
	if err != nil {
		stage := "sts_other_reject"
		if denyMarker == "attribute_condition" {
			stage = "sts_attribute_condition"
		} else if denyMarker == "invalid_signature" {
			stage = "sts_invalid_signature"
		}
		return nil, stage, status, denyMarker, tokenInfo, err
	}
	tokenInfo.Trusted = true
	if resourceMode == "kms" {
		data, stage, status, err := decryptFixture(ctx, accessToken)
		if stage == "kms_decrypt" && status == http.StatusForbidden {
			return nil, "resource_forbidden", status, "resource_forbidden", tokenInfo, err
		}
		return data, stage, status, "", tokenInfo, err
	}
	if resourceMode != "gcs" {
		return nil, "configuration", 0, "", tokenInfo, errors.New("resource mode is invalid")
	}
	bucket := strings.TrimSpace(fixtureBucket)
	object := strings.TrimSpace(fixtureObject)
	if bucket == "" || object == "" {
		return nil, "configuration", 0, "", tokenInfo, errors.New("fixture object is not configured")
	}

	endpoint := "https://storage.googleapis.com/storage/v1/b/" + url.PathEscape(bucket) + "/o/" + url.PathEscape(object) + "?alt=media"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "object_read", 0, "", tokenInfo, errors.New("could not construct object request")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, "object_read", 0, "", tokenInfo, errors.New("object request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			return nil, "resource_forbidden", resp.StatusCode, "resource_forbidden", tokenInfo, fmt.Errorf("object request returned HTTP %d", resp.StatusCode)
		}
		return nil, "object_read", resp.StatusCode, "", tokenInfo, fmt.Errorf("object request returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		return nil, "object_read", resp.StatusCode, "", tokenInfo, errors.New("object response unavailable or too large")
	}
	if negativeCase != "" {
		return body, "access_unexpectedly_allowed", resp.StatusCode, "unexpected_allow", tokenInfo, errors.New("access succeeded although denial was expected")
	}
	return body, "", resp.StatusCode, "", tokenInfo, nil
}

func compareTokenSignature(ctx context.Context, audience string, original []byte, summary tokenSummary) ([]byte, string, int, string, tokenSummary, error) {
	originalText := strings.TrimSpace(string(original))
	_, _, _, originalErr := exchangeToken(ctx, audience, originalText)
	if originalErr != nil {
		return nil, "signature_comparator_failed", 0, "", summary, errors.New("STS did not accept the unaltered control token")
	}
	mutated, err := alterJWTSignature(original)
	if err != nil {
		return nil, "token_fixture", 0, "", summary, err
	}
	_, status, marker, reject := exchangeToken(ctx, audience, string(mutated))
	_, _, _, stillValid := exchangeToken(ctx, audience, originalText)
	if reject == nil || stillValid != nil || (status != http.StatusBadRequest && status != http.StatusUnauthorized) || marker == "attribute_condition" {
		return nil, "signature_comparator_failed", 0, "", summary, errors.New("signature comparison did not show the expected STS outcomes")
	}
	return nil, "sts_invalid_signature", status, "invalid_signature", summary, errors.New("STS rejected only the token with the changed signature")
}

func exchangeToken(ctx context.Context, audience, subjectToken string) (string, int, string, error) {
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {audience},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
		"subject_token":        {subjectToken},
		"scope":                {"https://www.googleapis.com/auth/cloud-platform"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.googleapis.com/v1/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, "", errors.New("could not construct token exchange")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", 0, "", errors.New("token exchange request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		failureBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return "", resp.StatusCode, classifySTSError(failureBody), fmt.Errorf("token exchange returned HTTP %d", resp.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64*1024))
	if err := dec.Decode(&token); err != nil || token.AccessToken == "" {
		return "", resp.StatusCode, "", errors.New("token exchange response was invalid")
	}
	return token.AccessToken, resp.StatusCode, "", nil
}

func requestLauncherToken(ctx context.Context, audience, nonce string) ([]byte, error) {
	requestBody, err := json.Marshal(struct {
		Audience  string   `json:"audience"`
		TokenType string   `json:"token_type"`
		Nonces    []string `json:"nonces"`
	}{Audience: audience, TokenType: "OIDC", Nonces: []string{nonce}})
	if err != nil {
		return nil, errors.New("could not construct launcher token request")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", "/run/container_launcher/teeserver.sock")
		},
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/token", bytes.NewReader(requestBody))
	if err != nil {
		return nil, errors.New("could not construct launcher token request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("launcher token request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("launcher token request returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || len(body) == 0 {
		return nil, errors.New("launcher token response unavailable")
	}
	var tokenString string
	if json.Unmarshal(body, &tokenString) == nil && tokenString != "" {
		return []byte(tokenString), nil
	}
	var tokenObject struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(body, &tokenObject) == nil && tokenObject.Token != "" {
		return []byte(tokenObject.Token), nil
	}
	return bytes.TrimSpace(body), nil
}

func summarizeToken(token []byte, expectedNonce string) tokenSummary {
	parts := strings.Split(strings.TrimSpace(string(token)), ".")
	if len(parts) != 3 {
		return tokenSummary{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return tokenSummary{}
	}
	var claims struct {
		IssuedAt int64           `json:"iat"`
		HWModel  string          `json:"hwmodel"`
		Nonce    json.RawMessage `json:"eat_nonce"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return tokenSummary{}
	}
	summary := tokenSummary{HWModel: claims.HWModel}
	if claims.IssuedAt > 0 {
		summary.AgeSeconds = time.Now().Unix() - claims.IssuedAt
	}
	if len(claims.Nonce) > 0 {
		var one string
		if json.Unmarshal(claims.Nonce, &one) == nil {
			summary.NonceCount = 1
			summary.NonceMatch = expectedNonce != "" && one == expectedNonce
		} else {
			var many []string
			if json.Unmarshal(claims.Nonce, &many) == nil {
				summary.NonceCount = len(many)
				for _, value := range many {
					if expectedNonce != "" && value == expectedNonce {
						summary.NonceMatch = true
					}
				}
			}
		}
	}
	return summary
}

func decryptFixture(ctx context.Context, accessToken string) ([]byte, string, int, error) {
	if kmsKeyName == "" || !strings.HasPrefix(kmsKeyName, "projects/") || !strings.Contains(kmsKeyName, "/cryptoKeys/") {
		return nil, "configuration", 0, errors.New("KMS key resource is not configured")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("KMS_CIPHERTEXT_B64")))
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > 64*1024 {
		return nil, "configuration", 0, errors.New("KMS_CIPHERTEXT_B64 is invalid")
	}
	body, err := json.Marshal(map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(ciphertext)})
	if err != nil {
		return nil, "kms_decrypt", 0, errors.New("could not construct KMS request")
	}
	endpoint := "https://cloudkms.googleapis.com/v1/" + strings.TrimPrefix(kmsKeyName, "/") + ":decrypt"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "kms_decrypt", 0, errors.New("could not construct KMS request")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, "kms_decrypt", 0, errors.New("KMS request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "kms_decrypt", resp.StatusCode, fmt.Errorf("KMS request returned HTTP %d", resp.StatusCode)
	}
	var decoded struct {
		Plaintext string `json:"plaintext"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 128*1024))
	if err := dec.Decode(&decoded); err != nil {
		return nil, "kms_decrypt", resp.StatusCode, errors.New("KMS response was invalid")
	}
	plaintext, err := base64.StdEncoding.DecodeString(decoded.Plaintext)
	if err != nil || len(plaintext) > 64*1024 {
		return nil, "kms_decrypt", resp.StatusCode, errors.New("KMS plaintext response was invalid")
	}
	return plaintext, "", resp.StatusCode, nil
}

func classifySTSError(body []byte) string {
	var response struct {
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &response) != nil {
		return "sts_other_reject"
	}
	description := strings.ToLower(strings.TrimSpace(response.ErrorDescription))
	if strings.Contains(description, "the given credential is rejected by the attribute condition") {
		return "attribute_condition"
	}
	if strings.Contains(description, "invalid signature") || strings.Contains(description, "signature is invalid") || strings.Contains(description, "signature verification failed") {
		return "invalid_signature"
	}
	return "sts_other_reject"
}

func isDenyStage(stage string) bool {
	return stage == "sts_attribute_condition" || stage == "sts_invalid_signature" || stage == "sts_other_reject" || stage == "resource_forbidden"
}

func isExpectedDenial(expected, marker, stage string, status int) bool {
	if status < 400 || status > 499 {
		return false
	}
	switch expected {
	case "attribute_condition":
		return stage == "sts_attribute_condition" && marker == "attribute_condition"
	case "invalid_signature":
		return stage == "sts_invalid_signature" && marker == "invalid_signature"
	case "resource_forbidden":
		return stage == "resource_forbidden" && marker == "resource_forbidden"
	case "":
		return (stage == "sts_attribute_condition" && marker == "attribute_condition") ||
			(stage == "sts_invalid_signature" && marker == "invalid_signature") ||
			(stage == "resource_forbidden" && marker == "resource_forbidden")
	default:
		return false
	}
}

func alterJWTSignature(token []byte) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(string(token)), ".")
	if len(parts) != 3 || parts[2] == "" {
		return nil, errors.New("attestation token fixture is not a three-part JWT")
	}
	first := byte('A')
	if parts[2][0] == first {
		first = 'B'
	}
	parts[2] = string(first) + parts[2][1:]
	return []byte(strings.Join(parts, ".")), nil
}

// runInference is a tiny deterministic two-class linear inference fixture.
// Inputs and int8-like weights are synthetic constants, avoiding model/data
// dependencies while making the protected CPU path perform inference work.
func runInference(examples uint64) ([sha256.Size]byte, uint64) {
	inputs := [4][3]int64{{2, -1, 3}, {-2, 4, 1}, {0, 3, -2}, {5, 1, 0}}
	weights := [2][3]int64{{2, -1, 1}, {-1, 2, 1}}
	bias := [2]int64{1, -2}
	h := sha256.New()
	var encoded [24]byte
	var classZero uint64
	for i := uint64(0); i < examples; i++ {
		x := inputs[i%uint64(len(inputs))]
		var score [2]int64
		for c := 0; c < 2; c++ {
			score[c] = bias[c]
			for j := 0; j < len(x); j++ {
				score[c] += x[j] * weights[c][j]
			}
			binary.BigEndian.PutUint64(encoded[c*8:], uint64(score[c]))
		}
		predicted := uint64(1)
		if score[0] >= score[1] {
			predicted = 0
			classZero++
		}
		binary.BigEndian.PutUint64(encoded[16:], predicted)
		_, _ = h.Write(encoded[:])
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest, classZero
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func boundedUintEnv(name string, fallback, min, max uint64) (uint64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed < min || parsed > max {
		return 0, fmt.Errorf("%s is outside its permitted range", name)
	}
	return parsed, nil
}

func boolEnv(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return parsed, nil
}

func emit(res result) error {
	res.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(true)
	return enc.Encode(res)
}
