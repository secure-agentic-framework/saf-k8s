// Process-local AES-GCM key for an inert checkpoint stored on a disposable volume.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const (
	marker = "saf-k8s-0304-009 synthetic checkpoint marker v1"
	dir    = "/checkpoint"
	path   = dir + "/envelope.json"
)

var context = []byte("saf-k8s:0304-009:checkpoint:v1")

type envelope struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func fail(message string, err error) {
	fmt.Fprintln(os.Stderr, message, err)
	os.Exit(1)
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0600); err != nil {
		fail("write checkpoint", err)
	}
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fail("read checkpoint", err)
	}
	return data
}

func encode(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		fail("encode probe output", err)
	}
	return payload
}

func useCheckpoint(algorithm cipher.AEAD, path string) ([]byte, error) {
	var data envelope
	if err := json.Unmarshal(read(path), &data); err != nil {
		return nil, err
	}
	return algorithm.Open(nil, data.Nonce, data.Ciphertext, context)
}

func encrypted() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fail("generate case-local key", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fail("initialize AES", err)
	}
	algorithm, err := cipher.NewGCM(block)
	if err != nil {
		fail("initialize GCM", err)
	}
	nonce := make([]byte, algorithm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		fail("generate nonce", err)
	}
	sealed := envelope{Nonce: nonce, Ciphertext: algorithm.Seal(nil, nonce, []byte(marker), context)}
	write(path, encode(sealed))
	info, err := os.Stat(path)
	if err != nil {
		fail("inspect checkpoint mode", err)
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(dir, &filesystem); err != nil {
		fail("inspect checkpoint filesystem", err)
	}
	opened, err := useCheckpoint(algorithm, path)
	valid := err == nil && string(opened) == marker
	modified := append([]byte(nil), sealed.Ciphertext...)
	modified[len(modified)-1] ^= 1
	corruptedPath := dir + "/corrupted.json"
	write(corruptedPath, encode(envelope{Nonce: nonce, Ciphertext: modified}))
	_, corruptErr := useCheckpoint(algorithm, corruptedPath)
	fmt.Println(string(encode(map[string]any{
		"plain_marker_absent": !bytes.Contains(read(path), []byte(marker)),
		"disk_backed":         filesystem.Type != 0x01021994,
		"valid_accepted":      valid,
		"corrupted_rejected":  corruptErr != nil,
		"file_mode":           uint32(info.Mode().Perm()),
		"envelope":            sealed,
	})))
}

func observer() {
	deadline := time.Now().Add(20 * time.Second)
	for {
		_, err := os.Stat(path)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			fail("wait for checkpoint file", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	check := func(flags int) bool {
		file, err := os.OpenFile(path, flags, 0)
		if err == nil {
			file.Close()
		}
		return errors.Is(err, os.ErrPermission)
	}
	fmt.Println(string(encode(map[string]bool{"read_denied": check(os.O_RDONLY), "write_denied": check(os.O_WRONLY)})))
}

func main() {
	if len(os.Args) != 2 {
		fail("expected one fixture mode", nil)
	}
	switch os.Args[1] {
	case "plain":
		write(path, []byte(marker))
		fmt.Println(string(encode(map[string]bool{"plain_marker_present": bytes.Equal(read(path), []byte(marker))})))
	case "encrypt":
		encrypted()
	case "observe":
		observer()
	default:
		fail("unknown fixture mode", nil)
	}
}
