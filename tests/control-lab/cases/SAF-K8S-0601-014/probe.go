package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func main() {
	root := "writable"
	if err := os.WriteFile("/fixture-marker", []byte("public fixture"), 0); err != nil {
		if !errors.Is(err, syscall.EROFS) {
			fmt.Fprintf(os.Stderr, "unexpected root write outcome: %v\n", err)
			os.Exit(1)
		}
		root = "read-only"
	}

	const scratch = "/scratch/probe-marker"
	if err := os.WriteFile(scratch, []byte("public fixture"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write allowed scratch: %v\n", err)
		os.Exit(1)
	}
	if err := os.Remove(scratch); err != nil {
		fmt.Fprintf(os.Stderr, "remove allowed scratch: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("uid=%d rootfs=%s scratch=writable\n", os.Getuid(), root)
}
