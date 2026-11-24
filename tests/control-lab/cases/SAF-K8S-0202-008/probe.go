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

func fixtureClient(path string, groups []uint32) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(executable, "client", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: 65534, Gid: 65534, Groups: groups,
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
	world, err := fixtureClient(path, []uint32{})
	if err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	parent, err := fixtureClient(path, []uint32{})
	if err != nil {
		return err
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	mode, err := fixtureClient(path, []uint32{})
	if err != nil {
		return err
	}
	owner, err := echo(path)
	if err != nil {
		return err
	}
	const approvedGroup = 42424
	if err := os.Chown(path, 0, approvedGroup); err != nil {
		return err
	}
	if err := os.Chmod(path, 0660); err != nil {
		return err
	}
	inGroup, err := fixtureClient(path, []uint32{approvedGroup})
	if err != nil {
		return err
	}
	outOfGroup, err := fixtureClient(path, []uint32{})
	if err != nil {
		return err
	}
	fmt.Printf("public=%s parent=%s mode=%s owner=%s group=%s no_group=%s\n",
		world, parent, mode, owner, inGroup, outOfGroup)
	return nil
}

// This reads only POSIX access ACL metadata on the known Kind path. It
// never connects to the real socket or issues a runtime protocol request.
func runtimeACLs() error {
	for _, path := range []string{"/", "/run", "/run/containerd", "/run/containerd/containerd.sock"} {
		_, err := syscall.Getxattr(path, "system.posix_acl_access", nil)
		var state string
		switch {
		case errors.Is(err, syscall.ENODATA):
			state = "absent"
		case errors.Is(err, syscall.ENOTSUP):
			state = "unsupported"
		case err != nil:
			return err
		default:
			state = "present"
		}
		fmt.Printf("%s=%s\n", path, state)
	}
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
	} else if len(os.Args) == 2 && os.Args[1] == "runtime-acls" {
		err = runtimeACLs()
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
