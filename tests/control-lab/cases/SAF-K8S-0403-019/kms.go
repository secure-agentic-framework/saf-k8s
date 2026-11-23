package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	v2 "k8s.io/kms/apis/v2"
)

const keyID = "fixture-remote-kek-v1"

// Service wraps the Kubernetes DEK source under a separate authority's
// in-memory key. It exists solely inside a disposable fixture network.
type authority struct {
	kek   cipher.AEAD
	token string
}

type envelope struct {
	Data []byte `json:"data"`
}

func (a authority) serve(w http.ResponseWriter, r *http.Request) {
	credential := "Bearer " + a.token
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(credential)) != 1 {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/status":
		w.WriteHeader(http.StatusNoContent)
		return
	case r.Method != http.MethodPost:
		http.Error(w, "unknown operation", http.StatusNotFound)
		return
	}
	var input envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&input); err != nil {
		http.Error(w, "invalid envelope", http.StatusBadRequest)
		return
	}
	var output []byte
	switch r.URL.Path {
	case "/wrap":
		nonce := make([]byte, a.kek.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			http.Error(w, "randomness unavailable", http.StatusInternalServerError)
			return
		}
		output = a.kek.Seal(nonce, nonce, input.Data, []byte(keyID))
		fmt.Println("fixture-kms-wrap")
	case "/unwrap":
		n := a.kek.NonceSize()
		if len(input.Data) < n {
			http.Error(w, "invalid envelope", http.StatusBadRequest)
			return
		}
		plain, err := a.kek.Open(nil, input.Data[:n], input.Data[n:], []byte(keyID))
		if err != nil {
			http.Error(w, "invalid envelope", http.StatusBadRequest)
			return
		}
		output = plain
		fmt.Println("fixture-kms-unwrap")
	default:
		http.Error(w, "unknown operation", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(envelope{output}); err != nil {
		log.Print("fixture KMS response interrupted")
	}
}

func runAuthority(cert, key, token string) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	a := authority{aead, token}
	server := &http.Server{Addr: ":19443", Handler: http.HandlerFunc(a.serve), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 4 * time.Second, WriteTimeout: 4 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return server.ListenAndServeTLS(cert, key)
}

type plugin struct {
	v2.UnimplementedKeyManagementServiceServer
	address string
	token   string
	client  *http.Client
}

func (p *plugin) remote(ctx context.Context, method, route string, value []byte) ([]byte, error) {
	payload, err := json.Marshal(envelope{value})
	if err != nil {
		return nil, status.Error(codes.Internal, "fixture KMS encoding failed")
	}
	req, err := http.NewRequestWithContext(ctx, method, p.address+route, bytes.NewReader(payload))
	if err != nil {
		return nil, status.Error(codes.Internal, "fixture KMS request failed")
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "fixture KMS unavailable")
	}
	defer resp.Body.Close()
	if method == http.MethodGet && resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, status.Error(codes.Unavailable, "fixture KMS rejected the request")
	}
	var result envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&result); err != nil {
		return nil, status.Error(codes.Internal, "fixture KMS response invalid")
	}
	return result.Data, nil
}

func (p *plugin) Status(ctx context.Context, _ *v2.StatusRequest) (*v2.StatusResponse, error) {
	if _, err := p.remote(ctx, http.MethodGet, "/status", nil); err != nil {
		return nil, err
	}
	return &v2.StatusResponse{Version: "v2", Healthz: "ok", KeyId: keyID}, nil
}

func (p *plugin) Encrypt(ctx context.Context, req *v2.EncryptRequest) (*v2.EncryptResponse, error) {
	output, err := p.remote(ctx, http.MethodPost, "/wrap", req.Plaintext)
	if err != nil {
		return nil, err
	}
	return &v2.EncryptResponse{Ciphertext: output, KeyId: keyID}, nil
}

func (p *plugin) Decrypt(ctx context.Context, req *v2.DecryptRequest) (*v2.DecryptResponse, error) {
	if req.KeyId != keyID {
		return nil, status.Error(codes.InvalidArgument, "unknown fixture key")
	}
	output, err := p.remote(ctx, http.MethodPost, "/unwrap", req.Ciphertext)
	if err != nil {
		return nil, err
	}
	return &v2.DecryptResponse{Plaintext: output}, nil
}

func runPlugin(socket, address, caFile, token string) error {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid fixture CA")
	}
	p := &plugin{address: address, token: token, client: &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	grpcServer := grpc.NewServer()
	v2.RegisterKeyManagementServiceServer(grpcServer, p)
	return grpcServer.Serve(listener)
}

func main() {
	var err error
	switch {
	case len(os.Args) == 5 && os.Args[1] == "authority":
		var credentials []byte
		credentials, err = os.ReadFile(os.Args[4])
		if err == nil {
			err = runAuthority(os.Args[2], os.Args[3], strings.TrimSpace(string(credentials)))
		}
	case len(os.Args) == 6 && os.Args[1] == "plugin":
		var credentials []byte
		credentials, err = os.ReadFile(os.Args[5])
		if err == nil {
			err = runPlugin(os.Args[2], os.Args[3], os.Args[4], strings.TrimSpace(string(credentials)))
		}
	default:
		err = errors.New("unexpected fixture arguments")
	}
	if err != nil {
		log.Fatal(err)
	}
}
