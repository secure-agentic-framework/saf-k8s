package main

import (
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	contents, err := os.ReadFile("/app/payload.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read static payload: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("payload-sha256=%x\n", sha256.Sum256(contents))
}
