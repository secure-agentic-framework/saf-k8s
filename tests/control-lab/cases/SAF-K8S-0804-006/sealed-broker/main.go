//go:debug default=go1.24

// A disposable fixture for authenticated key release. All keys, measurements
// and ciphertext belong to the fixture and are generated afresh for each run.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	audience        = "saf-fixture-sealed-release"
	brokerURL       = "https://sealed-broker.saf-test.svc.cluster.local:8443"
	reviewURL       = "https://kubernetes.default.svc.cluster.local/apis/authentication.k8s.io/v1/tokenreviews"
	marker          = "saf-sealed-fixture-marker-v1"
	recipientKey    = "/scratch/recipient.der"
	recipientPublic = "/scratch/public.b64"
	signingDomain   = "saf-sealed-fixture-claims-v1\x00"
	maxDocument     = 32 << 10
)

type settings struct {
	RecipientKey       string `json:"recipient_pk"`
	IssuerPublic       string `json:"issuer_public"`
	Namespace          string `json:"namespace"`
	ServiceAccountName string `json:"service_account_name"`
	ServiceAccountUID  string `json:"service_account_uid"`
	PodUID             string `json:"pod_uid"`
}

type binding struct {
	ArtifactID      string `json:"artifact_id"`
	Policy          string `json:"policy"`
	Measurement     string `json:"measurement"`
	RecipientSHA256 string `json:"recipient_sha256"`
	Challenge       string `json:"challenge"`
	Subject         string `json:"subject"`
	SubjectUID      string `json:"subject_uid"`
	PodUID          string `json:"pod_uid"`
}

type artifactBinding struct {
	binding
	CiphertextSHA256 string `json:"ciphertext_sha256"`
}

type artifact struct {
	artifactBinding
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type claims struct {
	artifactBinding
	IssuedAt  int64 `json:"issued_at"`
	ExpiresAt int64 `json:"expires_at"`
}

type envelope struct {
	Claims    []byte `json:"claims"`
	Signature []byte `json:"signature"`
}

type release struct {
	Reason     string `json:"reason"`
	WrappedKey []byte `json:"wrapped_key,omitempty"`
}

type observation struct {
	Status             int    `json:"status"`
	Reason             string `json:"reason"`
	Opened             bool   `json:"opened"`
	ReturnedWrappedKey bool   `json:"returned_wrapped_key"`
	PlaintextSHA256    string `json:"plaintext_sha256"`
}

type reviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

type reviewRequest struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Spec       reviewSpec `json:"spec"`
}

type reviewStatus struct {
	Authenticated bool     `json:"authenticated"`
	Audiences     []string `json:"audiences"`
	Error         string   `json:"error"`
	User          struct {
		Username string              `json:"username"`
		UID      string              `json:"uid"`
		Extra    map[string][]string `json:"extra"`
	} `json:"user"`
}

type broker struct {
	artifact  artifact
	key       []byte
	recipient *rsa.PublicKey
	issuer    ed25519.PublicKey
	api       *http.Client
	mu        sync.Mutex
	spent     bool
}

func strictJSON(reader io.Reader, value any) error {
	data, err := io.ReadAll(io.LimitReader(reader, maxDocument+1))
	if err != nil || len(data) > maxDocument {
		return errors.New("invalid JSON body size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid JSON document")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func randomBytes(size int) ([]byte, error) {
	result := make([]byte, size)
	_, err := rand.Read(result)
	return result, err
}

func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func readBase64(path string) ([]byte, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(value)))
}

func writeBase64(path string, value []byte) error {
	encoded := base64.StdEncoding.EncodeToString(value) + "\n"
	return os.WriteFile(path, []byte(encoded), 0600)
}

func certificate(host string, parent *x509.Certificate, signingKey ed25519.PrivateKey) ([]byte, []byte, error) {
	public, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(30 * time.Minute),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if parent == nil {
		cert.IsCA = true
		cert.KeyUsage |= x509.KeyUsageCertSign
		parent, signingKey = cert, secret
	} else {
		cert.DNSNames = []string{host}
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, parent, public, signingKey)
	return der, secret, err
}

func initFixture(dir, host string) error {
	caDER, caKey, err := certificate("SAF sealed fixture CA", nil, nil)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	tlsDER, tlsKey, err := certificate(host, ca, ed25519.PrivateKey(caKey))
	if err != nil {
		return err
	}
	tlsPKCS8, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(tlsKey))
	if err != nil {
		return err
	}
	files := []struct {
		name, kind string
		der        []byte
	}{
		{"ca.crt", "CERTIFICATE", caDER},
		{"tls.crt", "CERTIFICATE", tlsDER},
		{"tls.key", "PRIVATE KEY", tlsPKCS8},
	}
	for _, file := range files {
		data := pem.EncodeToMemory(&pem.Block{Type: file.kind, Bytes: file.der})
		if err := os.WriteFile(filepath.Join(dir, file.name), data, 0600); err != nil {
			return err
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeBase64(filepath.Join(dir, "issuer-public.b64"), public); err != nil {
		return err
	}
	return writeBase64(filepath.Join(dir, "issuer-private.b64"), private)
}

func prepare() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	if err := os.WriteFile(recipientKey, x509.MarshalPKCS1PrivateKey(key), 0600); err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	if err := writeBase64(recipientPublic, publicDER); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func sign(path string) error {
	key, err := readBase64(path)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid issuer key")
	}
	var proof claims
	if err := strictJSON(os.Stdin, &proof); err != nil {
		return err
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(key, append([]byte(signingDomain), body...))
	return json.NewEncoder(os.Stdout).Encode(envelope{Claims: body, Signature: signature})
}

func trustedClient(caPath string) (*http.Client, error) {
	cert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return nil, errors.New("invalid fixture trust root")
	}
	return &http.Client{
		Timeout: 7 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func seal(config settings) (artifact, []byte, error) {
	context := binding{
		ArtifactID:  "fixture-broker-artifact-v1",
		Policy:      "fixture-seal-policy-v1",
		Measurement: digest([]byte("synthetic-workload-measurement-v1")),
		Subject:     "system:serviceaccount:" + config.Namespace + ":" + config.ServiceAccountName,
		SubjectUID:  config.ServiceAccountUID,
		PodUID:      config.PodUID,
	}
	recipientDER, err := base64.StdEncoding.DecodeString(config.RecipientKey)
	if err != nil {
		return artifact{}, nil, err
	}
	context.RecipientSHA256 = digest(recipientDER)
	challenge, err := randomBytes(32)
	if err != nil {
		return artifact{}, nil, err
	}
	context.Challenge = hex.EncodeToString(challenge)
	key, err := randomBytes(32)
	if err != nil {
		return artifact{}, nil, err
	}
	gcm, err := aead(key)
	if err != nil {
		return artifact{}, nil, err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return artifact{}, nil, err
	}
	aad, err := json.Marshal(context)
	if err != nil {
		return artifact{}, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(marker), aad)
	return artifact{
		artifactBinding: artifactBinding{binding: context, CiphertextSHA256: digest(ciphertext)},
		Nonce:           nonce,
		Ciphertext:      ciphertext,
	}, key, nil
}

func buildBroker() (*broker, error) {
	file, err := os.Open("/config/settings.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var config settings
	if err := strictJSON(file, &config); err != nil {
		return nil, err
	}
	if config.Namespace == "" || config.ServiceAccountName == "" ||
		config.ServiceAccountUID == "" || config.PodUID == "" {
		return nil, errors.New("missing Kubernetes identity")
	}
	recipientDER, err := base64.StdEncoding.DecodeString(config.RecipientKey)
	if err != nil {
		return nil, err
	}
	recipient, err := x509.ParsePKIXPublicKey(recipientDER)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := recipient.(*rsa.PublicKey)
	if !ok || rsaKey.Size() != 256 {
		return nil, errors.New("invalid fixture recipient key")
	}
	issuer, err := base64.StdEncoding.DecodeString(config.IssuerPublic)
	if err != nil || len(issuer) != ed25519.PublicKeySize {
		return nil, errors.New("invalid fixture issuer")
	}
	boundArtifact, key, err := seal(config)
	if err != nil {
		return nil, err
	}
	api, err := trustedClient("/identity/ca.crt")
	if err != nil {
		return nil, err
	}
	return &broker{artifact: boundArtifact, key: key, recipient: rsaKey, issuer: issuer, api: api}, nil
}

func (b *broker) review(ctx context.Context, callerToken string) (reviewStatus, error) {
	var tokenReview struct {
		Status reviewStatus `json:"status"`
	}
	apiToken, err := os.ReadFile("/identity/token")
	if err != nil {
		return tokenReview.Status, err
	}
	body, err := json.Marshal(reviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec:       reviewSpec{Token: callerToken, Audiences: []string{audience}},
	})
	if err != nil {
		return tokenReview.Status, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, reviewURL, bytes.NewReader(body))
	if err != nil {
		return tokenReview.Status, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(apiToken)))
	request.Header.Set("Content-Type", "application/json")
	response, err := b.api.Do(request)
	if err != nil {
		return tokenReview.Status, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return tokenReview.Status, errors.New("TokenReview rejected by Kubernetes")
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxDocument)).Decode(&tokenReview); err != nil {
		return tokenReview.Status, err
	}
	return tokenReview.Status, nil
}

func writeResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func deny(w http.ResponseWriter, status int, reason string) {
	writeResponse(w, status, release{Reason: reason})
}

func timeValid(proof claims, now int64) bool {
	return proof.IssuedAt >= now-600 && proof.IssuedAt <= now+5 &&
		proof.ExpiresAt > now && proof.ExpiresAt > proof.IssuedAt &&
		proof.ExpiresAt <= proof.IssuedAt+600
}

func exactly(values []string, desired string) bool {
	return len(values) == 1 && values[0] == desired
}

func (b *broker) releaseKey(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(token) == 0 {
		deny(w, http.StatusUnauthorized, "token")
		return
	}
	identity, err := b.review(r.Context(), token)
	if err != nil {
		deny(w, http.StatusServiceUnavailable, "review")
		return
	}
	// The authenticator can include its rejection reason for invalid tokens.
	// Inspect the returned audience as well as the authentication result.
	if !identity.Authenticated || identity.Error != "" || !exactly(identity.Audiences, audience) {
		deny(w, http.StatusUnauthorized, "token")
		return
	}
	want := b.artifact.artifactBinding
	if identity.User.Username != want.Subject || identity.User.UID != want.SubjectUID ||
		!exactly(identity.User.Extra["authentication.kubernetes.io/pod-uid"], want.PodUID) {
		deny(w, http.StatusForbidden, "recipient")
		return
	}
	var proof envelope
	if strictJSON(r.Body, &proof) != nil ||
		!ed25519.Verify(b.issuer, append([]byte(signingDomain), proof.Claims...), proof.Signature) {
		deny(w, http.StatusForbidden, "signature")
		return
	}
	var signed claims
	if strictJSON(bytes.NewReader(proof.Claims), &signed) != nil || signed.artifactBinding != want {
		deny(w, http.StatusForbidden, "binding")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !timeValid(signed, time.Now().Unix()) {
		deny(w, http.StatusForbidden, "time")
		return
	}
	if b.spent {
		deny(w, http.StatusConflict, "replay")
		return
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, b.recipient, b.key, []byte(want.CiphertextSHA256))
	if err != nil {
		deny(w, http.StatusInternalServerError, "wrap")
		return
	}
	b.spent = true
	clear(b.key)
	writeResponse(w, http.StatusOK, release{Reason: "released", WrappedKey: wrapped})
}

func serve() error {
	b, err := buildBroker()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /artifact", func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, http.StatusOK, b.artifact)
	})
	mux.HandleFunc("POST /release", b.releaseKey)
	server := &http.Server{
		Addr: ":8443", Handler: mux,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 4 * time.Second,
		ReadTimeout:       6 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// TLS handshake errors may include peer or request material.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return server.ListenAndServeTLS("/tls/tls.crt", "/tls/tls.key")
}

func fetchArtifact(client *http.Client) (artifact, error) {
	var result artifact
	response, err := client.Get(brokerURL + "/artifact")
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("artifact retrieval returned HTTP %d", response.StatusCode)
	}
	if err := strictJSON(response.Body, &result); err != nil {
		return result, err
	}
	if result.CiphertextSHA256 != digest(result.Ciphertext) {
		return result, errors.New("artifact ciphertext digest mismatch")
	}
	return result, nil
}

func openArtifact(value artifact, wrapped []byte) (string, error) {
	der, err := os.ReadFile(recipientKey)
	if err != nil {
		return "", err
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return "", err
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	if value.RecipientSHA256 != digest(public) {
		return "", errors.New("the artifact was released to a different key")
	}
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, []byte(value.CiphertextSHA256))
	if err != nil {
		return "", err
	}
	defer clear(secret)
	gcm, err := aead(secret)
	if err != nil {
		return "", err
	}
	if len(value.Nonce) != gcm.NonceSize() {
		return "", errors.New("artifact nonce has the wrong size")
	}
	aad, err := json.Marshal(value.binding)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, value.Nonce, value.Ciphertext, aad)
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	if !bytes.Equal(plaintext, []byte(marker)) {
		return "", errors.New("opened artifact differs from the inert fixture marker")
	}
	return digest(plaintext), nil
}

func doRequest(client *http.Client, choice string) error {
	var proof envelope
	if err := strictJSON(os.Stdin, &proof); err != nil {
		return err
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, brokerURL+"/release", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	switch choice {
	case "good", "wrong":
		token, err := os.ReadFile("/identity/" + choice)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	case "none":
	default:
		return errors.New("unknown fixture token choice")
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var result release
	if err := strictJSON(response.Body, &result); err != nil {
		return err
	}
	observed := observation{
		Status:             response.StatusCode,
		Reason:             result.Reason,
		ReturnedWrappedKey: len(result.WrappedKey) > 0,
	}
	if response.StatusCode == http.StatusOK {
		if result.Reason != "released" || len(result.WrappedKey) == 0 {
			return errors.New("broker returned an invalid success response")
		}
		value, err := fetchArtifact(client)
		if err != nil {
			return err
		}
		observed.PlaintextSHA256, err = openArtifact(value, result.WrappedKey)
		if err != nil {
			return err
		}
		observed.Opened = true
	} else if result.Reason == "" || result.WrappedKey != nil {
		return errors.New("broker returned an invalid denial response")
	}
	return json.NewEncoder(os.Stdout).Encode(observed)
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("specify a fixture command")
	}
	switch args[0] {
	case "fixture-init":
		if len(args) == 3 {
			return initFixture(args[1], args[2])
		}
	case "prepare":
		if len(args) == 1 {
			return prepare()
		}
	case "public":
		if len(args) == 1 {
			key, err := os.ReadFile(recipientPublic)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(key)
			return err
		}
	case "serve":
		if len(args) == 1 {
			return serve()
		}
	case "artifact", "request":
		client, err := trustedClient("/trust/ca.crt")
		if err != nil {
			return err
		}
		if args[0] == "request" && len(args) == 2 {
			return doRequest(client, args[1])
		}
		if args[0] == "artifact" && len(args) == 1 {
			value, err := fetchArtifact(client)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(value)
		}
	case "sign":
		if len(args) == 2 {
			return sign(args[1])
		}
	}
	return errors.New("invalid fixture command or arguments")
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
