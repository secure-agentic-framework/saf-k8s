package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	keyAnnotation = "saf.example.test/signature-key"
	sigAnnotation = "saf.example.test/signature"
	allowedKeyID  = "authorized-test"
)

type admissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *admissionRequest  `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}
type admissionRequest struct {
	UID       string `json:"uid"`
	Operation string `json:"operation"`
	Namespace string `json:"namespace"`
	Resource  struct {
		Resource string `json:"resource"`
	} `json:"resource"`
	DryRun bool            `json:"dryRun,omitempty"`
	Object json.RawMessage `json:"object"`
}
type admissionResponse struct {
	UID     string           `json:"uid"`
	Allowed bool             `json:"allowed"`
	Status  *admissionStatus `json:"status,omitempty"`
}
type admissionStatus struct {
	Code    int32  `json:"code,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}
type signedProjection struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   signedMetadata    `json:"metadata"`
	Data       map[string]string `json:"data"`
	BinaryData map[string]string `json:"binaryData"`
	Immutable  *bool             `json:"immutable,omitempty"`
}
type signedMetadata struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "generate-fixtures" {
		if err := generateFixtures(os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	keys := map[string]ed25519.PublicKey{}
	for id, path := range map[string]string{
		"authorized-test": "/fixtures/authorized-test-public.pem",
		"unrelated-test":  "/fixtures/unrelated-test-public.pem",
	} {
		key, err := readPublicKey(path)
		if err != nil {
			log.Fatal(err)
		}
		keys[id] = key
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		var review admissionReview
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&review); err != nil {
			http.Error(w, "invalid AdmissionReview JSON", http.StatusBadRequest)
			return
		}
		if review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" || review.Request == nil {
			http.Error(w, "expected admission.k8s.io/v1 AdmissionReview request", http.StatusBadRequest)
			return
		}
		allowed, message, projectionHash := verify(review.Request.Object, keys)
		objectHash := sha256.Sum256(review.Request.Object)
		log.Printf("review_uid=%q namespace=%q resource=%q operation=%q dry_run=%t object_json_sha256=%x projection_sha256=%s allowed=%t decision=%q",
			review.Request.UID, review.Request.Namespace, review.Request.Resource.Resource, review.Request.Operation, review.Request.DryRun,
			objectHash, projectionHash, allowed, message)
		response := admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
			Response: &admissionResponse{UID: review.Request.UID, Allowed: allowed}}
		if !allowed {
			response.Response.Status = &admissionStatus{Code: 403, Reason: "Forbidden", Message: message}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("encode response: %v", err)
		}
	})
	cert, err := tls.LoadX509KeyPair("/tls/tls.crt", "/tls/tls.key")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8443", Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s is not PEM", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not Ed25519", path)
	}
	return key, nil
}

func verify(raw json.RawMessage, keys map[string]ed25519.PublicKey) (bool, string, string) {
	var object struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name        string            `json:"name"`
			Namespace   string            `json:"namespace"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Data       map[string]string `json:"data"`
		BinaryData map[string]string `json:"binaryData"`
		Immutable  *bool             `json:"immutable,omitempty"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return false, "object is not valid JSON", ""
	}
	if object.APIVersion != "v1" || object.Kind != "ConfigMap" || object.Metadata.Name == "" || object.Metadata.Namespace == "" {
		return false, "object is outside the signed ConfigMap projection", ""
	}
	projection := signedProjection{APIVersion: object.APIVersion, Kind: object.Kind,
		Metadata: signedMetadata{Name: object.Metadata.Name, Namespace: object.Metadata.Namespace, Labels: object.Metadata.Labels}, Data: object.Data,
		BinaryData: object.BinaryData, Immutable: object.Immutable}
	payload, err := json.Marshal(projection)
	if err != nil {
		return false, "could not encode signed field projection", ""
	}
	digest := sha256.Sum256(payload)
	annotations := object.Metadata.Annotations
	if annotations == nil || annotations[sigAnnotation] == "" || annotations[keyAnnotation] == "" {
		return false, "signature is absent", fmt.Sprintf("%x", digest)
	}
	keyID := annotations[keyAnnotation]
	key, known := keys[keyID]
	if !known {
		return false, "signature identity is unknown", fmt.Sprintf("%x", digest)
	}
	signature, err := base64.StdEncoding.DecodeString(annotations[sigAnnotation])
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return false, "signature does not verify over the signed field projection", fmt.Sprintf("%x", digest)
	}
	if keyID != allowedKeyID {
		return false, "signature is valid but signer is not authorized", fmt.Sprintf("%x", digest)
	}
	return true, "authorized signature verified", fmt.Sprintf("%x", digest)
}

func generateFixtures(dir string) error {
	signers := map[string]ed25519.PrivateKey{}
	for _, id := range []string{"authorized-test", "unrelated-test"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		encoded, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}
		if err := writePEM(dir, id+"-public.pem", "PUBLIC KEY", encoded); err != nil {
			return err
		}
		signers[id] = key
	}
	for _, version := range []string{"create", "update"} {
		bytes, err := os.ReadFile(filepath.Join(dir, version+"-projection.json"))
		if err != nil {
			return err
		}
		for id, key := range signers {
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, bytes))
			if err := os.WriteFile(filepath.Join(dir, id+"-"+version+".sig"), []byte(sig), 0600); err != nil {
				return err
			}
		}
	}
	return generateTLS(dir)
}

func writePEM(dir, file, blockType string, encoded []byte) error {
	return os.WriteFile(filepath.Join(dir, file),
		pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: encoded}), 0600)
}

func generateTLS(dir string) error {
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "SAF isolated webhook fixture CA"}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "saf-signature-webhook.saf-test.svc"}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"saf-signature-webhook.saf-test.svc"}}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		return err
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}
	for _, asset := range []struct {
		file, kind string
		data       []byte
	}{
		{"webhook-ca.crt", "CERTIFICATE", caDER}, {"tls.crt", "CERTIFICATE", leafDER},
		{"tls.key", "PRIVATE KEY", keyDER},
	} {
		if err := writePEM(dir, asset.file, asset.kind, asset.data); err != nil {
			return err
		}
	}
	return nil
}
