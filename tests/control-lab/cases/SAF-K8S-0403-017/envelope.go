package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
)

type input struct {
	Mode string
	Key  []byte
	Data []byte
	AAD  string
}

func run() error {
	var request input
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	block, err := aes.NewCipher(request.Key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	n := aead.NonceSize()
	var output []byte
	switch request.Mode {
	case "seal":
		nonce := make([]byte, n)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		output = aead.Seal(nonce, nonce, request.Data, []byte(request.AAD))
	case "open":
		if len(request.Data) < n {
			return fmt.Errorf("invalid envelope")
		}
		output, err = aead.Open(nil, request.Data[:n], request.Data[n:], []byte(request.AAD))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown request")
	}
	return json.NewEncoder(os.Stdout).Encode(output)
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}
