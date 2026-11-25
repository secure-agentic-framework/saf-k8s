// AES-GCM protection for inert checkpoints on disposable volumes.
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
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	marker = "saf-k8s-0304-009 synthetic checkpoint marker v1"
	dir    = "/checkpoint"
	path   = dir + "/envelope.json"
)

var context = []byte("saf-k8s:0304-009:checkpoint:v1")

const (
	resumeKey   = "/resume-key/key"
	resumeRun   = "fixture-training-run-1"
	resumeStep  = 3
	resumeClock = 1767225600
	tmpfsMagic  = 0x01021994

	authRejected      = 20
	freshnessRejected = 21
	bindingRejected   = 22
)

var resumeContext = []byte("saf-k8s:0304-009:resume:v1")

type resumeRecord struct {
	Run       string `json:"run"`
	Step      int    `json:"step"`
	CreatedAt int64  `json:"created_at"`
	Payload   string `json:"payload"`
}

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

func openEnvelope(algorithm cipher.AEAD, data envelope, associated []byte) ([]byte, error) {
	if len(data.Nonce) != algorithm.NonceSize() {
		return nil, errors.New("invalid checkpoint nonce length")
	}
	return algorithm.Open(nil, data.Nonce, data.Ciphertext, associated)
}

func useCheckpoint(algorithm cipher.AEAD, path string, associated []byte) ([]byte, error) {
	var data envelope
	if err := json.Unmarshal(read(path), &data); err != nil {
		return nil, err
	}
	return openEnvelope(algorithm, data, associated)
}

func newKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fail("generate case-local key", err)
	}
	return key
}

func gcm(key []byte) cipher.AEAD {
	if len(key) != 32 {
		fail("expected an AES-256 key", nil)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fail("initialize AES", err)
	}
	algorithm, err := cipher.NewGCM(block)
	if err != nil {
		fail("initialize GCM", err)
	}
	return algorithm
}

func seal(algorithm cipher.AEAD, payload, associated []byte) envelope {
	nonce := make([]byte, algorithm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		fail("generate nonce", err)
	}
	return envelope{Nonce: nonce, Ciphertext: algorithm.Seal(nil, nonce, payload, associated)}
}

func encrypted() {
	algorithm := gcm(newKey())
	sealed := seal(algorithm, []byte(marker), context)
	write(path, encode(sealed))
	info, err := os.Stat(path)
	if err != nil {
		fail("inspect checkpoint mode", err)
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(dir, &filesystem); err != nil {
		fail("inspect checkpoint filesystem", err)
	}
	opened, err := useCheckpoint(algorithm, path, context)
	valid := err == nil && string(opened) == marker
	modified := append([]byte(nil), sealed.Ciphertext...)
	modified[len(modified)-1] ^= 1
	corruptedPath := dir + "/corrupted.json"
	write(corruptedPath, encode(envelope{Nonce: sealed.Nonce, Ciphertext: modified}))
	_, corruptErr := useCheckpoint(algorithm, corruptedPath, context)
	fmt.Println(string(encode(map[string]any{
		"plain_marker_absent": !bytes.Contains(read(path), []byte(marker)),
		"disk_backed":         filesystem.Type != tmpfsMagic,
		"valid_accepted":      valid,
		"corrupted_rejected":  corruptErr != nil,
		"file_mode":           uint32(info.Mode().Perm()),
		"envelope":            sealed,
	})))
}

// verifyResume is the single authenticated envelope gate shared by restore
// and promotion. Keep the expected run/step, AAD and time window here.
func verifyResume(file string) ([]byte, int) {
	algorithm := gcm(read(resumeKey))
	encoded := read(file)
	var sealed envelope
	if err := json.Unmarshal(encoded, &sealed); err != nil {
		fail("decode resume envelope", err)
	}
	plain, err := openEnvelope(algorithm, sealed, resumeContext)
	if err != nil {
		return nil, authRejected
	}

	var record resumeRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		fail("decode authenticated metadata", err)
	}
	if record.Run != resumeRun || record.Step != resumeStep || record.Payload != marker {
		return nil, bindingRejected
	}
	if record.CreatedAt > resumeClock || record.CreatedAt < resumeClock-300 {
		return nil, freshnessRejected
	}
	return encoded, 0
}

func resume(file string) int {
	_, status := verifyResume(file)
	if status != 0 {
		return status
	}
	fmt.Println("SAF-CHECKPOINT-RESUMED")
	return 0
}

func promotionDestination(file string) string {
	if filepath.Dir(file) != dir {
		fail("promotion source is outside the case-owned checkpoint directory", nil)
	}
	return filepath.Join(dir, "promoted-"+filepath.Base(file))
}

func promote(file string) int {
	// No destination path is accepted from the caller. A destination is derived
	// only inside the fixture-owned checkpoint directory after verifyResume passes.
	encoded, status := verifyResume(file)
	if status != 0 {
		return status
	}
	destination := promotionDestination(file)
	part := destination + ".part"
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		fail("promotion destination already exists", err)
	}
	if _, err := os.Lstat(part); !errors.Is(err, os.ErrNotExist) {
		fail("promotion temporary path already exists", err)
	}
	output, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fail("create approved promotion copy", err)
	}
	if _, err := output.Write(encoded); err != nil {
		output.Close()
		removeOwned(part)
		fail("write approved promotion copy", err)
	}
	if err := output.Sync(); err != nil {
		output.Close()
		removeOwned(part)
		fail("sync approved promotion copy", err)
	}
	if err := output.Close(); err != nil {
		removeOwned(part)
		fail("close approved promotion copy", err)
	}
	if err := os.Link(part, destination); err != nil {
		removeOwned(part)
		fail("publish approved promotion copy", err)
	}
	removeOwned(part)
	fmt.Println("SAF-CHECKPOINT-PROMOTED")
	return 0
}

// The fixture uses a fixed clock and case-owned files. Every read is made by a
// fresh program invocation against persisted bytes. Each denial has its own
// exit status so an execution, I/O or setup error cannot count as a pass.
func lifecycle() {
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/resume-key", &fs); err != nil || fs.Type != tmpfsMagic {
		fail("the per-Pod key volume must be tmpfs", err)
	}
	key := newKey()
	write(resumeKey, key)
	keyInfo, err := os.Stat(resumeKey)
	if err != nil || keyInfo.Mode().Perm() != 0600 {
		fail("inspect key file mode", err)
	}
	algorithm := gcm(key)
	record := resumeRecord{Run: resumeRun, Step: resumeStep, CreatedAt: resumeClock, Payload: marker}
	original := seal(algorithm, encode(record), resumeContext)
	modified := seal(algorithm, encode(record), resumeContext)
	modified.Ciphertext[len(modified.Ciphertext)-1] ^= 1
	wrongStep := record
	wrongStep.Step++
	wrongRun := record
	wrongRun.Run = "fixture-training-run-2"
	stale := record
	stale.CreatedAt -= 301
	future := record
	future.CreatedAt++

	probes := []struct {
		name       string
		sealed     envelope
		wantStatus int
	}{
		{"authorized_retained_verified", original, 0},
		{"changed_rejected", modified, authRejected},
		{"wrong_run_rejected", seal(algorithm, encode(wrongRun), resumeContext), bindingRejected},
		{"wrong_step_rejected", seal(algorithm, encode(wrongStep), resumeContext), bindingRejected},
		{"stale_rejected", seal(algorithm, encode(stale), resumeContext), freshnessRejected},
		{"future_rejected", seal(algorithm, encode(future), resumeContext), freshnessRejected},
	}

	checks := map[string]bool{"key_tmpfs_mode_0600": true}
	owned := make(map[string]string, len(probes))
	for _, probe := range probes {
		file := dir + "/" + probe.name + ".json"
		write(file, encode(probe.sealed))
		owned[probe.name] = file
		output, err := exec.Command(os.Args[0], "resume", file).CombinedOutput()
		status := 0
		if err != nil {
			var child *exec.ExitError
			if !errors.As(err, &child) {
				fail("start fresh resume process", err)
			}
			status = child.ExitCode()
		}
		expectedOutput := ""
		if probe.wantStatus == 0 {
			expectedOutput = "SAF-CHECKPOINT-RESUMED\n"
		}
		checks[probe.name] = status == probe.wantStatus && string(output) == expectedOutput
	}
	promotionChecks := make(map[string]bool, len(probes))
	for _, probe := range probes {
		file := owned[probe.name]
		destination := promotionDestination(file)
		part := destination + ".part"
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			fail("promotion destination must begin absent", err)
		}
		if _, err := os.Lstat(part); !errors.Is(err, os.ErrNotExist) {
			fail("promotion temporary path must begin absent", err)
		}
		output, err := exec.Command(os.Args[0], "promote", file).CombinedOutput()
		status := 0
		if err != nil {
			var child *exec.ExitError
			if !errors.As(err, &child) {
				fail("start fresh promotion consumer", err)
			}
			status = child.ExitCode()
		}
		expectedOutput := ""
		if probe.wantStatus == 0 {
			expectedOutput = "SAF-CHECKPOINT-PROMOTED\n"
		}
		if probe.wantStatus == 0 {
			data, readErr := os.ReadFile(destination)
			info, statErr := os.Stat(destination)
			_, verifyStatus := verifyResume(destination)
			_, partErr := os.Lstat(part)
			promotionChecks["approved_copy_written"] = status == 0 && string(output) == expectedOutput &&
				readErr == nil && statErr == nil && bytes.Equal(data, read(file)) &&
				!bytes.Contains(data, []byte(marker)) && verifyStatus == 0 &&
				info.Mode().Perm() == 0600 && errors.Is(partErr, os.ErrNotExist)
		} else {
			_, destinationErr := os.Lstat(destination)
			_, partErr := os.Lstat(part)
			promotionChecks["tampered_no_destination"] = promotionChecks["tampered_no_destination"] ||
				(probe.name == "changed_rejected" && status == probe.wantStatus && string(output) == "" &&
					errors.Is(destinationErr, os.ErrNotExist) && errors.Is(partErr, os.ErrNotExist))
			promotionChecks["wrong_run_no_destination"] = promotionChecks["wrong_run_no_destination"] ||
				(probe.name == "wrong_run_rejected" && status == probe.wantStatus && string(output) == "" &&
					errors.Is(destinationErr, os.ErrNotExist) && errors.Is(partErr, os.ErrNotExist))
			promotionChecks["wrong_step_no_destination"] = promotionChecks["wrong_step_no_destination"] ||
				(probe.name == "wrong_step_rejected" && status == probe.wantStatus && string(output) == "" &&
					errors.Is(destinationErr, os.ErrNotExist) && errors.Is(partErr, os.ErrNotExist))
			promotionChecks["stale_no_destination"] = promotionChecks["stale_no_destination"] ||
				(probe.name == "stale_rejected" && status == probe.wantStatus && string(output) == "" &&
					errors.Is(destinationErr, os.ErrNotExist) && errors.Is(partErr, os.ErrNotExist))
			promotionChecks["future_no_destination"] = promotionChecks["future_no_destination"] ||
				(probe.name == "future_rejected" && status == probe.wantStatus && string(output) == "" &&
					errors.Is(destinationErr, os.ErrNotExist) && errors.Is(partErr, os.ErrNotExist))
		}
	}
	for _, file := range owned {
		removeOwned(file)
		if filepath.Base(file) == "authorized_retained_verified.json" {
			removeOwned(promotionDestination(file))
		}
	}
	removeOwned(resumeKey)
	checks["cleanup_verified"] = true
	fmt.Println(string(encode(map[string]any{"resume": checks, "promotion": promotionChecks})))
}

func removeOwned(file string) {
	if err := os.Remove(file); err != nil {
		fail("remove owned lifecycle fixture", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		fail("verify lifecycle cleanup", err)
	}
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
	if len(os.Args) == 3 && os.Args[1] == "resume" {
		os.Exit(resume(os.Args[2]))
	}
	if len(os.Args) == 3 && os.Args[1] == "promote" {
		os.Exit(promote(os.Args[2]))
	}
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
	case "lifecycle":
		lifecycle()
	default:
		fail("unknown fixture mode", nil)
	}
}
