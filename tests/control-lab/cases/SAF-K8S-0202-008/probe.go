package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const marker = "saf-local-echo"

func echo(path string) (string, error) {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if errors.Is(err, syscall.EACCES) {
		return "denied", nil
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, marker); err != nil {
		return "", err
	}
	reply := make([]byte, len(marker))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return "", err
	}
	if string(reply) != marker {
		return "", errors.New("fixture echo mismatch")
	}
	return "echo", nil
}

func outsider(path string) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(executable, "client", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: 65534, Gid: 65534, Groups: []uint32{},
	}}
	observed, err := cmd.Output()
	return string(observed), err
}

func run() error {
	dir, err := os.MkdirTemp("/tmp", "saf-unix-echo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}
	path := filepath.Join(dir, "fixture.sock")
	server, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer server.Close()
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, len(marker))
			if conn.SetDeadline(time.Now().Add(time.Second)) == nil {
				if _, err := io.ReadFull(conn, buf); err == nil {
					_, _ = conn.Write(buf)
				}
			}
			_ = conn.Close()
		}
	}()

	if err := os.Chmod(path, 0666); err != nil {
		return err
	}
	world, err := outsider(path)
	if err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	parent, err := outsider(path)
	if err != nil {
		return err
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	mode, err := outsider(path)
	if err != nil {
		return err
	}
	owner, err := echo(path)
	if err != nil {
		return err
	}
	fmt.Printf("public=%s parent=%s mode=%s owner=%s\n", world, parent, mode, owner)
	return nil
}

func main() {
	var err error
	if len(os.Args) == 3 && os.Args[1] == "client" {
		if os.Geteuid() != 65534 || filepath.Base(os.Args[2]) != "fixture.sock" {
			err = errors.New("unrecognized fixture client context")
		} else {
			var result string
			result, err = echo(os.Args[2])
			if err == nil {
				fmt.Print(result)
			}
		}
	} else if len(os.Args) == 1 {
		err = run()
	} else {
		err = errors.New("unrecognized arguments")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
