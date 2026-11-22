// Package main implements a narrowly scoped Ed25519 WorkflowTemplate admission verifier.
// The host runner uses the same canonical() and decide() functions to create fixtures.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	keyAnnotation = "saf.example.test/signature-key"
	sigAnnotation = "saf.example.test/signature"
	trustedID     = "trusted-fixture"
	untrustedID   = "untrusted-fixture"
	caseNamespace = "saf-signing-admission"
	domain        = "SAF-K8S-0904-017\x00WorkflowTemplate\x00v1"
	image         = "docker.io/library/golang:1.26.11-alpine3.24@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab"
)

type metadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
type resource struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   metadata        `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
}
type projection struct {
	Domain     string          `json:"domain"`
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   signedMetadata  `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
}
type signedMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

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
		Group    string `json:"group"`
		Resource string `json:"resource"`
	} `json:"resource"`
	Kind struct {
		Group   string `json:"group"`
		Version string `json:"version"`
		Kind    string `json:"kind"`
	} `json:"kind"`
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

func main() {
	if len(os.Args) == 4 && os.Args[1] == "material" {
		if err := generateMaterial(os.Args[2], os.Args[3]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "tls-material" {
		if err := tlsMaterial(os.Args[2], os.Args[3]); err != nil {
			log.Fatal(err)
		}
		return
	}
	dns := os.Getenv("SERVICE_DNS")
	if dns == "" {
		log.Fatal("SERVICE_DNS is required")
	}
	var resolved bool
	for i := 0; i < 30; i++ {
		if _, err := net.LookupHost(dns); err == nil {
			resolved = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !resolved {
		log.Fatal("service DNS did not resolve")
	}
	log.Printf("service_dns_observed=%s", dns)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.WriteString(w, os.Getenv("SERVICE_DNS")+"\n")
	})
	mux.HandleFunc("/validate", handleValidate)
	cert, err := tls.LoadX509KeyPair("/cache/tls/tls.crt", "/cache/tls/tls.key")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8443", Handler: mux, ReadHeaderTimeout: 3 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	var review admissionReview
	if err := dec.Decode(&review); err != nil {
		http.Error(w, "invalid AdmissionReview JSON", http.StatusBadRequest)
		return
	}
	if review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" || review.Request == nil {
		http.Error(w, "expected admission.k8s.io/v1 AdmissionReview", http.StatusBadRequest)
		return
	}
	req := review.Request
	allowed, reason := false, "malformed admission request"
	if req.Operation == "CREATE" || req.Operation == "UPDATE" {
		if req.Namespace == caseNamespace && req.Resource.Group == "argoproj.io" && req.Resource.Resource == "workflowtemplates" &&
			req.Kind.Group == "argoproj.io" && req.Kind.Version == "v1alpha1" && req.Kind.Kind == "WorkflowTemplate" {
			allowed, reason = decide(req.Object, loadPublicKeys())
		} else {
			reason = "request is outside the selected WorkflowTemplate resource"
		}
	} else {
		reason = "operation is outside CREATE and UPDATE"
	}
	response := admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
		Response: &admissionResponse{UID: req.UID, Allowed: allowed}}
	if !allowed {
		response.Response.Status = &admissionStatus{Code: 403, Reason: "Forbidden", Message: reason}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func loadPublicKeys() map[string]ed25519.PublicKey {
	keys := map[string]ed25519.PublicKey{}
	for id := range map[string]bool{trustedID: true, untrustedID: true} {
		b, err := os.ReadFile(filepath.Join("/cache/material", id+".pub"))
		if err != nil {
			log.Printf("public key read failed")
			continue
		}
		block, _ := pem.Decode(b)
		if block == nil {
			continue
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		key, ok := parsed.(ed25519.PublicKey)
		if ok {
			keys[id] = key
		}
	}
	return keys
}

// canonical emits sorted object keys and exact normalized base-10 JSON numbers.
// This preserves integer/decimal magnitude without float64 rounding and makes 1, 1.0,
// and 1e0 the same signed value. Exponents are bounded to keep canonicalization bounded.
func canonical(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if x {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(x)
		out.Write(b)
	case json.Number:
		n, err := normalizeNumber(x.String())
		if err != nil {
			return err
		}
		out.WriteString(n)
	case []any:
		out.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			out.Write(kb)
			out.WriteByte(':')
			if err := writeCanonical(out, x[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON type %T", v)
	}
	return nil
}

func normalizeNumber(s string) (string, error) {
	if len(s) == 0 || len(s) > 4096 {
		return "", errors.New("invalid numeric length")
	}
	neg := false
	if s[0] == '-' {
		neg = true
		s = s[1:]
	}
	parts := strings.SplitN(s, "e", 2)
	if len(parts) == 1 {
		parts = strings.SplitN(s, "E", 2)
	}
	exp := int64(0)
	if len(parts) == 2 {
		n, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil || n > 10000 || n < -10000 {
			return "", errors.New("numeric exponent out of range")
		}
		exp = n
	}
	mant := strings.SplitN(parts[0], ".", 2)
	frac := 0
	digits := mant[0]
	if len(mant) == 2 {
		frac = len(mant[1])
		digits += mant[1]
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", errors.New("invalid JSON number")
		}
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0", nil
	}
	point := int64(len(digits)) + exp - int64(frac)
	// Reconstruct using original decimal point offset after removing leading zeros.
	original := mant[0] + func() string {
		if len(mant) == 2 {
			return mant[1]
		}
		return ""
	}()
	leading := len(original) - len(strings.TrimLeft(original, "0"))
	point = int64(len(original)-leading) + exp - int64(frac)
	for len(digits) > 1 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
	}
	var value string
	if point <= 0 {
		value = "0." + strings.Repeat("0", int(-point)) + digits
	} else if point >= int64(len(digits)) {
		value = digits + strings.Repeat("0", int(point-int64(len(digits))))
	} else {
		value = digits[:point] + "." + digits[point:]
	}
	if neg {
		value = "-" + value
	}
	return value, nil
}

func canonicalPayload(raw []byte) ([]byte, error) {
	var obj resource
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if obj.APIVersion != "argoproj.io/v1alpha1" || obj.Kind != "WorkflowTemplate" || obj.Metadata.Name == "" || obj.Metadata.Namespace != caseNamespace || len(obj.Spec) == 0 || string(obj.Spec) == "null" {
		return nil, errors.New("object is outside signed WorkflowTemplate projection")
	}
	spec, err := canonical(obj.Spec)
	if err != nil {
		return nil, err
	}
	p := projection{Domain: domain, APIVersion: obj.APIVersion, Kind: obj.Kind,
		Metadata: signedMetadata{Name: obj.Metadata.Name, Namespace: obj.Metadata.Namespace}, Spec: spec}
	return json.Marshal(p)
}

func decide(raw []byte, keys map[string]ed25519.PublicKey) (bool, string) {
	var obj resource
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false, "object is not valid WorkflowTemplate JSON"
	}
	payload, err := canonicalPayload(raw)
	if err != nil {
		return false, "object is outside signed WorkflowTemplate projection"
	}
	a := obj.Metadata.Annotations
	if a == nil || a[keyAnnotation] == "" || a[sigAnnotation] == "" {
		return false, "signature is absent"
	}
	id := a[keyAnnotation]
	key, ok := keys[id]
	if !ok {
		return false, "signature identity is unknown"
	}
	sig, err := base64.StdEncoding.DecodeString(a[sigAnnotation])
	if err != nil || !ed25519.Verify(key, payload, sig) {
		return false, "signature does not verify over canonical WorkflowTemplate identity and spec"
	}
	if id != trustedID {
		return false, "signature is valid but fixture identity is not trusted"
	}
	return true, "trusted signature verified"
}

func generateMaterial(dir, fixture string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	pubs := map[string]ed25519.PublicKey{}
	privs := map[string]ed25519.PrivateKey{}
	for _, id := range []string{trustedID, untrustedID} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		pubs[id] = pub
		privs[id] = priv
	}
	for id, pub := range pubs {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, id+".pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
			return err
		}
	}
	b, err := os.ReadFile(fixture)
	if err != nil {
		return err
	}
	unsigned := b
	objects := map[string]json.RawMessage{}
	makeSigned := func(id string, source []byte, sign bool) ([]byte, error) {
		var o map[string]any
		d := json.NewDecoder(bytes.NewReader(source))
		d.UseNumber()
		if e := d.Decode(&o); e != nil {
			return nil, e
		}
		meta := o["metadata"].(map[string]any)
		anns := map[string]any{}
		meta["annotations"] = anns
		objBytes, e := json.Marshal(o)
		if e != nil {
			return nil, e
		}
		if sign {
			payload, e := canonicalPayload(objBytes)
			if e != nil {
				return nil, e
			}
			anns[keyAnnotation] = id
			anns[sigAnnotation] = base64.StdEncoding.EncodeToString(ed25519.Sign(privs[id], payload))
			objBytes, e = json.Marshal(o)
			if e != nil {
				return nil, e
			}
		}
		return objBytes, nil
	}
	u, err := makeSigned(trustedID, unsigned, false)
	if err != nil {
		return err
	}
	objects["unsigned"] = u
	trusted, err := makeSigned(trustedID, unsigned, true)
	if err != nil {
		return err
	}
	objects["trusted"] = trusted
	untrusted, err := makeSigned(untrustedID, unsigned, true)
	if err != nil {
		return err
	}
	objects["untrusted"] = untrusted
	var changed map[string]any
	d := json.NewDecoder(bytes.NewReader(unsigned))
	d.UseNumber()
	if err = d.Decode(&changed); err != nil {
		return err
	}
	spec := changed["spec"].(map[string]any)
	templates := spec["templates"].([]any)
	container := templates[0].(map[string]any)["container"].(map[string]any)
	container["args"] = []any{"false"}
	changedRaw, err := json.Marshal(changed)
	if err != nil {
		return err
	}
	changedSigned, err := makeSigned(trustedID, changedRaw, false)
	if err != nil {
		return err
	}
	var changedMap, trustedMap map[string]any
	_ = json.Unmarshal(changedSigned, &changedMap)
	_ = json.Unmarshal(trusted, &trustedMap)
	changedMap["metadata"].(map[string]any)["annotations"] = trustedMap["metadata"].(map[string]any)["annotations"]
	changedSigned, err = json.Marshal(changedMap)
	if err != nil {
		return err
	}
	objects["changed_trusted"] = changedSigned
	trustedUpdate, err := makeSigned(trustedID, changedRaw, true)
	if err != nil {
		return err
	}
	objects["trusted_update"] = trustedUpdate
	out, err := json.MarshalIndent(objects, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "objects.json"), append(out, '\n'), 0600)
}

// tlsMaterial creates a short-lived serving certificate with the exact service FQDN.
func tlsMaterial(dir, dns string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "saf ephemeral webhook CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, pub, priv)
	if err != nil {
		return err
	}
	leafPub, leafPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns, strings.TrimSuffix(dns, ".cluster.local")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caTmpl, leafPub, priv)
	if err != nil {
		return err
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	key, err := x509.MarshalPKCS8PrivateKey(leafPriv)
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{"ca.crt": ca, "tls.crt": crt, "tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return err
		}
	}
	_ = leafPriv
	return nil
}
