// Serve only Git upload-pack for the case-owned fixture repositories.
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const prefix = "/fixture/"

func main() {
	gitPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		log.Fatal(err)
	}
	backend := filepath.Join(strings.TrimSpace(string(gitPath)), "git-http-backend")
	info, err := os.Stat(backend)
	if err != nil {
		log.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		log.Fatalf("fixture Git HTTP backend is not executable at %s", backend)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ready")
	})
	mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		repo, operation, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, prefix), "/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch repo {
		case "baseline-unsigned.git", "trusted-signed.git", "untrusted-signed.git":
		default:
			http.NotFound(w, r)
			return
		}
		discover := r.Method == http.MethodGet && operation == "info/refs" &&
			r.URL.RawQuery == "service=git-upload-pack"
		fetch := r.Method == http.MethodPost && operation == "git-upload-pack" &&
			r.URL.RawQuery == ""
		if !discover && !fetch {
			http.Error(w, "Only fixture Git reads are served", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		handler := cgi.Handler{
			Path: backend,
			Dir:  "/tools/repos",
			Root: strings.TrimSuffix(prefix, "/"),
			Env: []string{
				"PATH=" + os.Getenv("PATH"),
				"GIT_PROJECT_ROOT=/tools/repos",
			},
			Stderr: os.Stderr,
		}
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
