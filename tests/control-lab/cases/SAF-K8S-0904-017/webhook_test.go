package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeNumberExact(t *testing.T) {
	for input, expected := range map[string]string{
		"1": "1", "1.0": "1", "1e0": "1", "1000.00": "1000",
		"0.00120": "0.0012", "-0.0": "0", "1.25e2": "125",
		"9007199254740993": "9007199254740993",
	} {
		got, err := normalizeNumber(input)
		if err != nil || got != expected {
			t.Fatalf("normalizeNumber(%q) = %q, %v; want %q", input, got, err, expected)
		}
	}
}

func TestCanonicalNumericRepresentationsMatch(t *testing.T) {
	a, err := canonical([]byte(`{"z":1.0,"a":[1e0,9007199254740993]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonical([]byte(`{"a":[1,9007199254740993.0],"z":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical forms differ: %s != %s", a, b)
	}
}

func TestDecisionBindsIdentityAndFullSpec(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{trustedID: pub}
	base := []byte(`{"apiVersion":"argoproj.io/v1alpha1","kind":"WorkflowTemplate","metadata":{"name":"fixed","namespace":"saf-signing-admission","annotations":{"saf.example.test/signature-key":"trusted-fixture"}},"spec":{"entrypoint":"x","replicas":1}}`)
	payload, err := canonicalPayload(base)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err = json.Unmarshal(base, &obj); err != nil {
		t.Fatal(err)
	}
	meta := obj["metadata"].(map[string]any)
	anns := meta["annotations"].(map[string]any)
	anns[sigAnnotation] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	signed, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := decide(signed, keys); !ok || reason != "trusted signature verified" {
		t.Fatalf("valid fixture denied: %v %s", ok, reason)
	}
	changed := []byte(string(signed))
	var changedObj map[string]any
	if err = json.Unmarshal(changed, &changedObj); err != nil {
		t.Fatal(err)
	}
	changedObj["spec"].(map[string]any)["replicas"] = json.Number("2")
	changed, err = json.Marshal(changedObj)
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := decide(changed, keys); ok || reason != "signature does not verify over canonical WorkflowTemplate identity and spec" {
		t.Fatalf("changed spec decision: %v %s", ok, reason)
	}
	changedObj["metadata"].(map[string]any)["name"] = "different"
	changed, err = json.Marshal(changedObj)
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := decide(changed, keys); ok || reason != "signature does not verify over canonical WorkflowTemplate identity and spec" {
		t.Fatalf("changed identity decision: %v %s", ok, reason)
	}
}

func TestServingCertificateMatchesWebhookService(t *testing.T) {
	const serviceName = "saf-workflow-signature.saf-signing-admission.svc"
	dir := t.TempDir()
	if err := tlsMaterial(dir, serviceName+".cluster.local"); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("could not read fixture CA")
	}
	public, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(public)
	if block == nil {
		t.Fatal("could not decode fixture serving certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{serviceName, serviceName + ".cluster.local"} {
		if _, err := cert.Verify(x509.VerifyOptions{DNSName: name, Roots: pool}); err != nil {
			t.Errorf("serving certificate could not authenticate %q: %v", name, err)
		}
	}
}

func TestFixedSpecChangeWithFreshSignature(t *testing.T) {
	dir := t.TempDir()
	if err := generateMaterial(dir, "fixtures/workflow-template.json"); err != nil {
		t.Fatal(err)
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, identity := range []string{trustedID, untrustedID} {
		data, err := os.ReadFile(filepath.Join(dir, identity+".pub"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatal("could not decode fixture public key")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		keys[identity] = key.(ed25519.PublicKey)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "objects.json"))
	if err != nil {
		t.Fatal(err)
	}
	var objects map[string]json.RawMessage
	if err := json.Unmarshal(raw, &objects); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"unsigned": false, "changed_trusted": false, "untrusted": false,
		"trusted": true, "trusted_update": true}
	if len(objects) != len(want) {
		t.Fatalf("unexpected fixture set size %d", len(objects))
	}
	for name, shouldAllow := range want {
		if allowed, reason := decide(objects[name], keys); allowed != shouldAllow {
			t.Errorf("unexpected decision %t for %s (%s)", allowed, name, reason)
		}
	}
}
