package main

import (
	"bytes"
	"context"
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
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	v2 "k8s.io/kms/apis/v2"
)

type plugin struct {
	v2.UnimplementedKeyManagementServiceServer
	address string
	token   string
	key     string
	client  *http.Client
}

type response struct {
	Data struct {
		LatestVersion int    `json:"latest_version"`
		Ciphertext    string `json:"ciphertext"`
		Plaintext     []byte `json:"plaintext"`
	} `json:"data"`
}

func (p *plugin) access(ctx context.Context, method, operation string, payload any) (response, error) {
	var result response
	data, err := json.Marshal(payload)
	if err != nil {
		return result, status.Error(codes.Internal, "fixture transit request invalid")
	}
	request, err := http.NewRequestWithContext(ctx, method, p.address+"/v1/transit/"+operation+"/"+p.key, bytes.NewReader(data))
	if err != nil {
		return result, status.Error(codes.Internal, "fixture transit request unavailable")
	}
	request.Header.Set("X-Vault-Token", p.token)
	request.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(request)
	if err != nil {
		return result, status.Error(codes.Unavailable, "fixture Vault unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, status.Error(codes.PermissionDenied, "fixture Vault operation rejected")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&result); err != nil {
		return result, status.Error(codes.Internal, "fixture transit response invalid")
	}
	return result, nil
}

func (p *plugin) keyID(version int) string {
	return p.key + "-v" + strconv.Itoa(version)
}

func (p *plugin) Status(ctx context.Context, _ *v2.StatusRequest) (*v2.StatusResponse, error) {
	result, err := p.access(ctx, http.MethodGet, "keys", nil)
	if err != nil {
		return nil, err
	}
	if result.Data.LatestVersion < 1 {
		return nil, status.Error(codes.Unavailable, "fixture key version unavailable")
	}
	return &v2.StatusResponse{Version: "v2", Healthz: "ok", KeyId: p.keyID(result.Data.LatestVersion)}, nil
}

func (p *plugin) Encrypt(ctx context.Context, req *v2.EncryptRequest) (*v2.EncryptResponse, error) {
	result, err := p.access(ctx, http.MethodPost, "encrypt", map[string][]byte{"plaintext": req.Plaintext})
	if err != nil {
		return nil, err
	}
	fields := strings.Split(result.Data.Ciphertext, ":")
	if len(fields) != 3 || fields[0] != "vault" || !strings.HasPrefix(fields[1], "v") {
		return nil, status.Error(codes.Internal, "fixture transit envelope invalid")
	}
	version, err := strconv.Atoi(strings.TrimPrefix(fields[1], "v"))
	if err != nil || version < 1 {
		return nil, status.Error(codes.Internal, "fixture transit envelope version invalid")
	}
	return &v2.EncryptResponse{Ciphertext: []byte(result.Data.Ciphertext), KeyId: p.keyID(version)}, nil
}

func (p *plugin) Decrypt(ctx context.Context, req *v2.DecryptRequest) (*v2.DecryptResponse, error) {
	if !strings.HasPrefix(req.KeyId, p.key+"-v") {
		return nil, status.Error(codes.InvalidArgument, "unknown fixture key")
	}
	result, err := p.access(ctx, http.MethodPost, "decrypt", map[string]string{"ciphertext": string(req.Ciphertext)})
	if err != nil {
		return nil, err
	}
	return &v2.DecryptResponse{Plaintext: result.Data.Plaintext}, nil
}

func run() error {
	if len(os.Args) != 7 {
		return errors.New("unexpected fixture arguments")
	}
	socket, address, host, caPath, tokenPath, key := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6]
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	root := x509.NewCertPool()
	if !root.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid fixture CA")
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	p := &plugin{address: address, token: strings.TrimSpace(string(token)), key: key,
		client: &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: root, ServerName: host, MinVersion: tls.VersionTLS12},
		}}}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	rpc := grpc.NewServer()
	v2.RegisterKeyManagementServiceServer(rpc, p)
	return rpc.Serve(listener)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
