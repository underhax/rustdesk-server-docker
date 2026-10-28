package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	errMockExec      = errors.New("simulated exec error")
	errMockReadDir   = errors.New("simulated readdir error")
	errMockRead      = errors.New("simulated read error")
	errMockDial      = errors.New("simulated dial error")
	errMockClose     = errors.New("simulated close error")
	errMockOpen      = errors.New("simulated open error")
	errMockWrite     = errors.New("simulated write error")
	errMockScrub     = errors.New("simulated scrub error")
	errMockMkdirAll  = errors.New("simulated mkdir error")
	errMockGenerate  = errors.New("simulated generate key error")
	errMockWriteFile = errors.New("simulated writefile error")
)

var (
	recordedExitCode     = -1
	recordedExecRole     string
	recordedExecArgs     []string
	recordedExecEnv      []string
	recordedExecAddr     string
	mockTargetSecretPath string
	mockFailWriteTarget  string
	redirectedSecretsDir string
	mockProcDirectory    string
	mockDialAttemptCount int
)

func mockExit(code int) {
	recordedExitCode = code
}

func mockFailingReadDir(_ string) ([]fs.DirEntry, error) {
	return nil, errMockReadDir
}

func mockFailingReadFile(_ string) ([]byte, error) {
	return nil, errMockRead
}

func mockFailingMkdirAll(_ string, _ os.FileMode) error {
	return errMockMkdirAll
}

type mockFailingReader struct{}

func (mockFailingReader) Read(_ []byte) (int, error) {
	return 0, errMockRead
}

func mockFailingGenerateKey(_ io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return nil, nil, errMockGenerate
}

func mockFailingWriteFile(_ string, _ []byte, _ os.FileMode) error {
	return errMockWriteFile
}

func mockConditionalWriteFile(name string, data []byte, perm os.FileMode) error {
	if mockFailWriteTarget != "" && strings.HasSuffix(name, mockFailWriteTarget) {
		return errMockWriteFile
	}
	return defaultWriteFile(name, data, perm)
}

func mockConditionalReadFile(path string) ([]byte, error) {
	if mockTargetSecretPath != "" && path == mockTargetSecretPath {
		return nil, errMockRead
	}
	return defaultReadFile(path)
}

func mockRedirectedReadFile(path string) ([]byte, error) {
	base := filepath.Base(path)
	return defaultReadFile(filepath.Join(redirectedSecretsDir, base))
}

func mockRedirectedReadDir(_ string) ([]fs.DirEntry, error) {
	return defaultReadDir(redirectedSecretsDir)
}

func mockSuccessfulExec(_ context.Context, role string, args, env []string, readinessAddr string) error {
	recordedExecRole = role
	recordedExecArgs = args
	recordedExecEnv = env
	recordedExecAddr = readinessAddr
	return nil
}

func mockFailingExec(_ context.Context, _ string, _, _ []string, _ string) error {
	return errMockExec
}

func mockNonExistentCommand(ctx context.Context, _ string, _ []string) *exec.Cmd {
	return exec.CommandContext(ctx, "/dev/null/non_existent_binary")
}

func mockTrueCommand(ctx context.Context, _ string, _ []string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

func mockFalseCommand(ctx context.Context, _ string, _ []string) *exec.Cmd {
	return exec.CommandContext(ctx, "false")
}

func mockFailingScrub(_ context.Context, _ int, _ string) error {
	return errMockScrub
}

type mockSocketDialer struct {
	conn net.Conn
	err  error
}

func (m *mockSocketDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.conn, nil
}

var activeMockDialer = &mockSocketDialer{}

func mockCreateDialer() socketDialer {
	return activeMockDialer
}

type mockSuccessConn struct {
	net.Conn
}

func (m *mockSuccessConn) Close() error {
	return nil
}

func mockSuccessDialTCP(_ context.Context, _, _ string) (net.Conn, error) {
	return &mockSuccessConn{}, nil
}

func mockFailingDialTCP(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errMockDial
}

type mockErrorCloserConn struct {
	net.Conn
}

func (m *mockErrorCloserConn) Close() error {
	return errMockClose
}

func mockErrorCloserDialTCP(_ context.Context, _, _ string) (net.Conn, error) {
	return &mockErrorCloserConn{}, nil
}

func mockRetrySuccessDialTCP(_ context.Context, _, _ string) (net.Conn, error) {
	mockDialAttemptCount++
	if mockDialAttemptCount == 1 {
		return nil, errMockDial
	}
	return &mockSuccessConn{}, nil
}

func mockProcPath(pid int, entry string) string {
	if mockProcDirectory != "" {
		return filepath.Join(mockProcDirectory, strconv.Itoa(pid), entry)
	}
	return defaultProcPath(pid, entry)
}

func mockFailingOpenFile(_ string, _ int, _ os.FileMode) (*os.File, error) {
	return nil, errMockOpen
}

func mockPermissionOpenFile(_ string, _ int, _ os.FileMode) (*os.File, error) {
	return nil, os.ErrPermission
}

func mockPermissionReadFile(_ string) ([]byte, error) {
	return nil, os.ErrPermission
}

func mockFailingWriteMemory(_ *os.File, _ []byte, _ int64) (int, error) {
	return 0, errMockWrite
}

func mockPermissionWriteMemory(_ *os.File, _ []byte, _ int64) (int, error) {
	return 0, os.ErrPermission
}

func mockFailingCloseFile(_ *os.File) error {
	return errMockClose
}

func mockPermissionCloseFile(_ *os.File) error {
	return os.ErrPermission
}

func createTestEd25519Keypair() (skBase64, pkBase64 string) {
	keyBytes := make([]byte, ed25519SecretKeyBytes)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	skBase64 = base64.StdEncoding.EncodeToString(keyBytes)
	pkBase64 = base64.StdEncoding.EncodeToString(keyBytes[ed25519PublicKeyBytes:ed25519SecretKeyBytes])
	return skBase64, pkBase64
}

func TestDefaultReadFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "sample.txt")
	expectedContent := []byte("secret_value")

	if err := os.WriteFile(filePath, expectedContent, 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	data, err := defaultReadFile(filePath)
	if err != nil {
		t.Fatalf("unexpected error reading file: %v", err)
	}

	if !bytes.Equal(data, expectedContent) {
		t.Fatalf("expected content %q, got %q", expectedContent, data)
	}

	if _, err := defaultReadFile(filepath.Join(tempDir, "non_existent.txt")); err == nil {
		t.Fatal("expected error reading non-existent file, got nil")
	}
}

func TestDefaultReadDir(t *testing.T) {
	tempDir := t.TempDir()

	entries, err := defaultReadDir(tempDir)
	if err != nil {
		t.Fatalf("unexpected error reading directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}

	if _, err := defaultReadDir(filepath.Join(tempDir, "non_existent_dir")); err == nil {
		t.Fatal("expected error reading non-existent directory, got nil")
	}
}

func TestDefaultCreateCommand(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		role     string
		args     []string
		wantPath string
		wantArgs []string
	}{
		{
			name:     "empty_args",
			role:     targetHbbs,
			args:     nil,
			wantPath: defaultHbbsBinaryPath,
			wantArgs: []string{defaultHbbsBinaryPath},
		},
		{
			name:     "binary_only",
			role:     targetHbbs,
			args:     []string{targetHbbs},
			wantPath: defaultHbbsBinaryPath,
			wantArgs: []string{defaultHbbsBinaryPath},
		},
		{
			name:     "with_arguments",
			role:     targetHbbr,
			args:     []string{targetHbbr, "-k", "custom_key"},
			wantPath: defaultHbbrBinaryPath,
			wantArgs: []string{defaultHbbrBinaryPath, "-k", "custom_key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := defaultCreateCommand(ctx, tt.role, tt.args)
			if cmd == nil {
				t.Fatal("expected command object, got nil")
			}
			if cmd.Path != tt.wantPath {
				t.Fatalf("expected command path %q, got %q", tt.wantPath, cmd.Path)
			}
			if !slices.Equal(cmd.Args, tt.wantArgs) {
				t.Fatalf("expected args %v, got %v", tt.wantArgs, cmd.Args)
			}
			if cmd.Cancel == nil {
				t.Fatal("expected cancel function, got nil")
			}
			if cmd.WaitDelay != 5*time.Second {
				t.Fatalf("expected wait delay 5s, got %v", cmd.WaitDelay)
			}
			if err := cmd.Cancel(); err != nil {
				t.Fatalf("unexpected cancel error: %v", err)
			}
		})
	}

	runningCmd := exec.CommandContext(ctx, "sleep", "10")
	cancelFn := cancelCommand(runningCmd)
	if err := runningCmd.Start(); err != nil {
		t.Fatalf("cmd.Start() unexpected error: %v", err)
	}
	defer func() {
		if waitErr := runningCmd.Wait(); waitErr != nil {
			if _, ok := errors.AsType[*exec.ExitError](waitErr); !ok {
				t.Errorf("runningCmd.Wait() error: %v", waitErr)
			}
		}
	}()
	if err := cancelFn(); err != nil {
		t.Fatalf("cancelFn() unexpected error: %v", err)
	}
}

func TestDefaultExec(t *testing.T) {
	ctx := context.Background()
	origCreate := createCommand
	origScrub := scrubChildMemory
	t.Cleanup(func() {
		createCommand = origCreate
		scrubChildMemory = origScrub
	})

	createCommand = mockNonExistentCommand
	if err := defaultExec(ctx, targetHbbs, nil, nil, "127.0.0.1:21116"); err == nil {
		t.Fatal("expected error executing non-existent binary, got nil")
	}

	createCommand = mockFalseCommand
	if err := defaultExec(ctx, targetHbbs, nil, nil, "127.0.0.1:21116"); err == nil {
		t.Fatal("expected error when command exits with failure, got nil")
	}

	createCommand = mockTrueCommand
	scrubChildMemory = mockFailingScrub
	if err := defaultExec(ctx, targetHbbs, nil, nil, "127.0.0.1:21116"); err != nil {
		t.Fatalf("unexpected error executing true binary with failing scrub: %v", err)
	}

	scrubChildMemory = origScrub
	if err := defaultExec(ctx, targetHbbs, nil, nil, "127.0.0.1:21116"); err != nil {
		t.Fatalf("unexpected error executing true binary: %v", err)
	}
}

func TestReadOptionalSecret(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "optional.txt")

	val, exists, err := readOptionalSecret(filePath)
	if err != nil {
		t.Fatalf("unexpected error for missing secret: %v", err)
	}
	if exists || val != "" {
		t.Fatalf("expected non-existent secret to return exists=false and val=\"\", got %v, %q", exists, val)
	}

	if writeErr := os.WriteFile(filePath, []byte("   trimmed_value   \n"), 0o600); writeErr != nil {
		t.Fatalf("writing secret file: %v", writeErr)
	}

	val, exists, err = readOptionalSecret(filePath)
	if err != nil {
		t.Fatalf("unexpected error reading secret: %v", err)
	}
	if !exists || val != "trimmed_value" {
		t.Fatalf("expected exists=true and trimmed value, got %v, %q", exists, val)
	}

	origReadFile := readFile
	readFile = mockFailingReadFile
	t.Cleanup(func() { readFile = origReadFile })

	if _, _, err := readOptionalSecret(filePath); err == nil {
		t.Fatal("expected read failure error, got nil")
	}
}

func TestReadRequiredSecret(t *testing.T) {
	tempDir := t.TempDir()
	secretName := "required.txt"
	filePath := filepath.Join(tempDir, secretName)

	if _, err := readRequiredSecret(tempDir, secretName); err == nil {
		t.Fatal("expected error for missing required secret, got nil")
	}

	if err := os.WriteFile(filePath, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("writing empty secret file: %v", err)
	}

	if _, err := readRequiredSecret(tempDir, secretName); err == nil {
		t.Fatal("expected error for whitespace-only secret, got nil")
	}

	if err := os.WriteFile(filePath, []byte("valid_secret"), 0o600); err != nil {
		t.Fatalf("writing valid secret: %v", err)
	}

	val, err := readRequiredSecret(tempDir, secretName)
	if err != nil {
		t.Fatalf("unexpected error reading required secret: %v", err)
	}
	if val != "valid_secret" {
		t.Fatalf("expected \"valid_secret\", got %q", val)
	}

	origReadFile := readFile
	readFile = mockFailingReadFile
	t.Cleanup(func() { readFile = origReadFile })

	if _, err := readRequiredSecret(tempDir, secretName); err == nil {
		t.Fatal("expected read error, got nil")
	}
}

func TestSetEnvVar(t *testing.T) {
	tests := []struct {
		name     string
		initial  []string
		key      string
		value    string
		expected []string
	}{
		{
			name:     "append_new_variable",
			initial:  []string{"EXISTING=1"},
			key:      "NEW_KEY",
			value:    "value",
			expected: []string{"EXISTING=1", "NEW_KEY=value"},
		},
		{
			name:     "replace_existing_variable",
			initial:  []string{"TARGET=old", "OTHER=2"},
			key:      "TARGET",
			value:    "new",
			expected: []string{"TARGET=new", "OTHER=2"},
		},
		{
			name:     "empty_initial_slice",
			initial:  nil,
			key:      "TARGET",
			value:    "val",
			expected: []string{"TARGET=val"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := setEnvVar(tt.initial, tt.key, tt.value)
			if !slices.Equal(res, tt.expected) {
				t.Fatalf("expected env %v, got %v", tt.expected, res)
			}
		})
	}
}

func TestListSecretNames(t *testing.T) {
	tempDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tempDir, "file_b"), []byte("b"), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "file_a"), []byte("a"), 0o600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(tempDir, "sub_dir"), 0o750); err != nil {
		t.Fatalf("creating subdirectory: %v", err)
	}

	names, err := listSecretNames(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedNames := []string{"file_a", "file_b"}
	if !slices.Equal(names, expectedNames) {
		t.Fatalf("expected names %v, got %v", expectedNames, names)
	}

	missingNames, err := listSecretNames(filepath.Join(tempDir, "non_existent_folder"))
	if err != nil {
		t.Fatalf("unexpected error for non-existent dir: %v", err)
	}
	if missingNames != nil {
		t.Fatalf("expected nil for non-existent directory, got %v", missingNames)
	}

	origReadDir := readDir
	readDir = mockFailingReadDir
	t.Cleanup(func() { readDir = origReadDir })

	if _, err := listSecretNames(tempDir); err == nil {
		t.Fatal("expected error scanning directory, got nil")
	}
}

func TestHasRustdeskSecretPrefix(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		expected bool
	}{
		{name: "lowercase_prefix", fileName: "rd_relay_address", expected: true},
		{name: "uppercase_prefix", fileName: "RD_RELAY_SERVERS", expected: true},
		{name: "mixed_case_prefix", fileName: "Rd_rendezvous", expected: true},
		{name: "prefix_only", fileName: rustdeskSecretPrefix, expected: true},
		{name: "unrelated_file", fileName: "id_ed25519", expected: false},
		{name: "prefix_at_end", fileName: "domain_rd_", expected: false},
		{name: "short_name", fileName: "rd", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRustdeskSecretPrefix(tt.fileName); got != tt.expected {
				t.Fatalf("expected %v for %q, got %v", tt.expected, tt.fileName, got)
			}
		})
	}
}

func TestIsInvalidEnvKeyRune(t *testing.T) {
	tests := []struct {
		name     string
		char     rune
		expected bool
	}{
		{name: "uppercase_a", char: 'A', expected: false},
		{name: "uppercase_z", char: 'Z', expected: false},
		{name: "digit_zero", char: '0', expected: false},
		{name: "digit_nine", char: '9', expected: false},
		{name: "underscore", char: '_', expected: false},
		{name: "lowercase_a", char: 'a', expected: true},
		{name: "hyphen", char: '-', expected: false},
		{name: "dot", char: '.', expected: true},
		{name: "equals", char: '=', expected: true},
		{name: "space", char: ' ', expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInvalidEnvKeyRune(tt.char); got != tt.expected {
				t.Fatalf("expected %v for rune %q, got %v", tt.expected, tt.char, got)
			}
		})
	}
}

func TestSecretEnvKey(t *testing.T) {
	tests := []struct {
		name      string
		fileName  string
		wantKey   string
		expectErr bool
	}{
		{name: "simple_relay", fileName: "rd_relay-servers", wantKey: "RELAY-SERVERS", expectErr: false},
		{name: "underscore_relay", fileName: "rd_relay_servers", wantKey: "RELAY_SERVERS", expectErr: false},
		{name: "rendezvous_key", fileName: "rd_rendezvous_servers", wantKey: "RENDEZVOUS_SERVERS", expectErr: false},
		{name: "uppercase_input", fileName: "RD_ALWAYS_USE_RELAY", wantKey: "ALWAYS_USE_RELAY", expectErr: false},
		{name: "digits_and_underscores", fileName: "rd_port_21116_ready", wantKey: "PORT_21116_READY", expectErr: false},
		{name: "empty_after_prefix", fileName: rustdeskSecretPrefix, wantKey: "", expectErr: true},
		{name: "short_length", fileName: "r", wantKey: "", expectErr: true},
		{name: "contains_dot", fileName: "rd_domain.name", wantKey: "", expectErr: true},
		{name: "contains_equal", fileName: "rd_key=value", wantKey: "", expectErr: true},
		{name: "contains_space", fileName: "rd_key name", wantKey: "", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := secretEnvKey(tt.fileName)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for file %q, got nil", tt.fileName)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for file %q: %v", tt.fileName, err)
			}
			if key != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, key)
			}
		})
	}
}

func TestDecodeBase64Key(t *testing.T) {
	rawBytes := []byte("example_test_key_bytes_123456789")
	padded := base64.StdEncoding.EncodeToString(rawBytes)
	unpadded := base64.RawStdEncoding.EncodeToString(rawBytes)

	decodedPadded, err := decodeBase64Key(padded)
	if err != nil {
		t.Fatalf("unexpected error decoding padded: %v", err)
	}
	if !bytes.Equal(decodedPadded, rawBytes) {
		t.Fatalf("expected %q, got %q", rawBytes, decodedPadded)
	}

	decodedUnpadded, err := decodeBase64Key(unpadded)
	if err != nil {
		t.Fatalf("unexpected error decoding unpadded: %v", err)
	}
	if !bytes.Equal(decodedUnpadded, rawBytes) {
		t.Fatalf("expected %q, got %q", rawBytes, decodedUnpadded)
	}

	if _, err := decodeBase64Key("!@#$invalid_base64"); err == nil {
		t.Fatal("expected error decoding invalid base64, got nil")
	}
}

func TestConfigureDynamicSecrets(t *testing.T) {
	tempDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tempDir, "rd_relay-servers"), []byte("relay.example.org\n"), 0o600); err != nil {
		t.Fatalf("writing secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "rd_empty"), []byte("   \n"), 0o600); err != nil {
		t.Fatalf("writing secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "ignored_secret"), []byte("value"), 0o600); err != nil {
		t.Fatalf("writing secret: %v", err)
	}

	names := []string{"ignored_secret", "rd_empty", "rd_relay-servers"}
	env, err := configureDynamicSecrets([]string{"INITIAL=true"}, tempDir, names)
	if err != nil {
		t.Fatalf("unexpected error configuring dynamic secrets: %v", err)
	}

	if !slices.Contains(env, "RELAY-SERVERS=relay.example.org") {
		t.Fatal("expected RELAY-SERVERS to be configured")
	}
	if slices.ContainsFunc(env, func(s string) bool { return strings.HasPrefix(s, "EMPTY=") }) {
		t.Fatal("expected empty secret not to be set")
	}

	invalidNames := []string{rustdeskSecretPrefix}
	if _, err := configureDynamicSecrets(nil, tempDir, invalidNames); err == nil {
		t.Fatal("expected error for invalid dynamic secret name, got nil")
	}

	origReadFile := readFile
	mockTargetSecretPath = filepath.Join(tempDir, "rd_relay-servers")
	readFile = mockConditionalReadFile
	t.Cleanup(func() {
		readFile = origReadFile
		mockTargetSecretPath = ""
	})

	if _, err := configureDynamicSecrets(nil, tempDir, names); err == nil {
		t.Fatal("expected error when reading secret fails, got nil")
	}
}

func TestConfigureHbbsKeySecrets(t *testing.T) {
	skBase64, pkBase64 := createTestEd25519Keypair()

	tests := []struct {
		name      string
		skContent string
		pkContent string
		writeSk   bool
		writePk   bool
		expectErr bool
	}{
		{
			name:      "valid_matching_keys",
			skContent: skBase64,
			pkContent: pkBase64,
			writeSk:   true,
			writePk:   true,
			expectErr: false,
		},
		{
			name:      "missing_sk_file",
			skContent: "",
			pkContent: pkBase64,
			writeSk:   false,
			writePk:   true,
			expectErr: true,
		},
		{
			name:      "missing_pk_file",
			skContent: skBase64,
			pkContent: "",
			writeSk:   true,
			writePk:   false,
			expectErr: true,
		},
		{
			name:      "corrupt_sk_base64",
			skContent: "!!!invalid_base64",
			pkContent: pkBase64,
			writeSk:   true,
			writePk:   true,
			expectErr: true,
		},
		{
			name:      "corrupt_pk_base64",
			skContent: skBase64,
			pkContent: "!!!invalid_base64",
			writeSk:   true,
			writePk:   true,
			expectErr: true,
		},
		{
			name:      "invalid_sk_size",
			skContent: base64.StdEncoding.EncodeToString(make([]byte, 16)),
			pkContent: pkBase64,
			writeSk:   true,
			writePk:   true,
			expectErr: true,
		},
		{
			name:      "invalid_pk_size",
			skContent: skBase64,
			pkContent: base64.StdEncoding.EncodeToString(make([]byte, 16)),
			writeSk:   true,
			writePk:   true,
			expectErr: true,
		},
		{
			name:      "mismatched_keys",
			skContent: skBase64,
			pkContent: base64.StdEncoding.EncodeToString(make([]byte, ed25519PublicKeyBytes)),
			writeSk:   true,
			writePk:   true,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subDir := t.TempDir()
			if tt.writeSk {
				if err := os.WriteFile(filepath.Join(subDir, fileIDEd25519), []byte(tt.skContent), 0o600); err != nil {
					t.Fatalf("writing sk: %v", err)
				}
			}
			if tt.writePk {
				if err := os.WriteFile(filepath.Join(subDir, fileIDEd25519Pub), []byte(tt.pkContent), 0o600); err != nil {
					t.Fatalf("writing pk: %v", err)
				}
			}

			env, err := configureHbbsKeySecrets(nil, subDir)
			if tt.expectErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Contains(env, "KEY="+tt.skContent) {
				t.Fatal("expected KEY to match secret key")
			}
			if !slices.Contains(env, "ENCRYPTED_ONLY=1") {
				t.Fatal("expected ENCRYPTED_ONLY=1 to be set")
			}
		})
	}
}

func TestConfigureHbbrKeySecrets(t *testing.T) {
	_, pkBase64 := createTestEd25519Keypair()

	tests := []struct {
		name      string
		pkContent string
		writePk   bool
		expectErr bool
	}{
		{
			name:      "valid_public_key",
			pkContent: pkBase64,
			writePk:   true,
			expectErr: false,
		},
		{
			name:      "missing_pk_file",
			pkContent: "",
			writePk:   false,
			expectErr: true,
		},
		{
			name:      "corrupt_pk_base64",
			pkContent: "@@@corrupt_base64",
			writePk:   true,
			expectErr: true,
		},
		{
			name:      "invalid_pk_size",
			pkContent: base64.StdEncoding.EncodeToString(make([]byte, 10)),
			writePk:   true,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subDir := t.TempDir()
			if tt.writePk {
				if err := os.WriteFile(filepath.Join(subDir, fileIDEd25519Pub), []byte(tt.pkContent), 0o600); err != nil {
					t.Fatalf("writing pk: %v", err)
				}
			}

			env, err := configureHbbrKeySecrets(nil, subDir)
			if tt.expectErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Contains(env, "KEY="+tt.pkContent) {
				t.Fatal("expected KEY to match public key")
			}
		})
	}
}

func TestConfigureEnforcedSettings(t *testing.T) {
	initial := []string{
		"HOME=/root",
		"OTHER=custom",
	}

	env := configureEnforcedSettings(initial)

	expectedSettings := []struct {
		key   string
		value string
	}{
		{key: "SSL_CERT_FILE", value: defaultSSLCertFile},
		{key: "SSL_CERT_DIR", value: defaultSSLCertDir},
		{key: "HOME", value: defaultHomeDir},
		{key: "OTHER", value: "custom"},
	}

	for _, s := range expectedSettings {
		expectedKV := s.key + "=" + s.value
		if !slices.Contains(env, expectedKV) {
			t.Fatalf("expected enforced setting %q in %v", expectedKV, env)
		}
	}
}

func TestResolveTargetCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantBinary  string
		wantRole    string
		wantCmdArgs []string
		expectErr   bool
	}{
		{
			name:        "empty_arguments",
			args:        nil,
			wantBinary:  "",
			wantRole:    "",
			wantCmdArgs: nil,
			expectErr:   true,
		},
		{
			name:        "hbbs_short",
			args:        []string{targetHbbs},
			wantBinary:  defaultHbbsBinaryPath,
			wantRole:    targetHbbs,
			wantCmdArgs: []string{targetHbbs},
			expectErr:   false,
		},
		{
			name:        "hbbs_full_path_with_flags",
			args:        []string{defaultHbbsBinaryPath, "-r", "relay.example.com"},
			wantBinary:  defaultHbbsBinaryPath,
			wantRole:    targetHbbs,
			wantCmdArgs: []string{targetHbbs, "-r", "relay.example.com"},
			expectErr:   false,
		},
		{
			name:        "hbbr_short",
			args:        []string{targetHbbr},
			wantBinary:  defaultHbbrBinaryPath,
			wantRole:    targetHbbr,
			wantCmdArgs: []string{targetHbbr},
			expectErr:   false,
		},
		{
			name:        "hbbr_full_path",
			args:        []string{defaultHbbrBinaryPath},
			wantBinary:  defaultHbbrBinaryPath,
			wantRole:    targetHbbr,
			wantCmdArgs: []string{targetHbbr},
			expectErr:   false,
		},
		{
			name:        "unknown_binary_target",
			args:        []string{"vaultwarden"},
			wantBinary:  "",
			wantRole:    "",
			wantCmdArgs: nil,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binaryPath, role, cmdArgs, err := ResolveTargetCommand(tt.args)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if binaryPath != tt.wantBinary || role != tt.wantRole {
				t.Fatalf("expected (%q, %q), got (%q, %q)", tt.wantBinary, tt.wantRole, binaryPath, role)
			}
			if !slices.Equal(cmdArgs, tt.wantCmdArgs) {
				t.Fatalf("expected cmdArgs %v, got %v", tt.wantCmdArgs, cmdArgs)
			}
		})
	}
}

func TestResolveReadinessAddress(t *testing.T) {
	if addr := resolveReadinessAddress(targetHbbr); addr != "127.0.0.1:21117" {
		t.Fatalf("expected 127.0.0.1:21117, got %q", addr)
	}
	if addr := resolveReadinessAddress(targetHbbs); addr != "127.0.0.1:21116" {
		t.Fatalf("expected 127.0.0.1:21116, got %q", addr)
	}
}

func TestPrepareEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	skBase64, pkBase64 := createTestEd25519Keypair()

	if err := os.WriteFile(filepath.Join(tempDir, fileIDEd25519), []byte(skBase64), 0o600); err != nil {
		t.Fatalf("writing sk: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, fileIDEd25519Pub), []byte(pkBase64), 0o600); err != nil {
		t.Fatalf("writing pk: %v", err)
	}

	hbbsEnv, err := PrepareEnvironment([]string{"BASE=1"}, tempDir, targetHbbs)
	if err != nil {
		t.Fatalf("unexpected error preparing hbbs env: %v", err)
	}
	if !slices.Contains(hbbsEnv, "KEY="+skBase64) {
		t.Fatal("expected KEY to match secret key")
	}

	hbbrEnv, err := PrepareEnvironment(nil, tempDir, targetHbbr)
	if err != nil {
		t.Fatalf("unexpected error preparing hbbr env: %v", err)
	}
	if !slices.Contains(hbbrEnv, "KEY="+pkBase64) {
		t.Fatal("expected KEY to match public key")
	}

	if _, err := PrepareEnvironment(nil, tempDir, "unknown"); err == nil {
		t.Fatal("expected error for unknown role, got nil")
	}

	origReadDir := readDir
	readDir = mockFailingReadDir
	t.Cleanup(func() { readDir = origReadDir })

	if _, err := PrepareEnvironment(nil, tempDir, targetHbbs); err == nil {
		t.Fatal("expected error on readdir failure, got nil")
	}
	readDir = origReadDir

	emptyDir := t.TempDir()
	if _, err := PrepareEnvironment(nil, emptyDir, targetHbbs); err == nil {
		t.Fatal("expected error for hbbs on missing keys, got nil")
	}
	if _, err := PrepareEnvironment(nil, emptyDir, targetHbbr); err == nil {
		t.Fatal("expected error for hbbr on missing keys, got nil")
	}

	invalidDynamicDir := t.TempDir()
	if err := os.WriteFile(filepath.Clean(filepath.Join(invalidDynamicDir, "rd_invalid.key")), []byte("val"), 0o600); err != nil {
		t.Fatalf("writing invalid dynamic secret: %v", err)
	}
	if _, err := PrepareEnvironment(nil, invalidDynamicDir, targetHbbs); err == nil {
		t.Fatal("expected error on invalid dynamic secret key name, got nil")
	}
}

func TestRun(t *testing.T) {
	tempDir := t.TempDir()
	skBase64, pkBase64 := createTestEd25519Keypair()

	if err := os.WriteFile(filepath.Join(tempDir, fileIDEd25519), []byte(skBase64), 0o600); err != nil {
		t.Fatalf("writing sk: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, fileIDEd25519Pub), []byte(pkBase64), 0o600); err != nil {
		t.Fatalf("writing pk: %v", err)
	}

	origExec := execProcess
	execProcess = mockSuccessfulExec
	t.Cleanup(func() { execProcess = origExec })

	ctx := context.Background()
	if err := Run(ctx, []string{targetHbbs, "-r", "relay.example.org"}, tempDir); err != nil {
		t.Fatalf("unexpected error in Run: %v", err)
	}

	expectedArgs := []string{targetHbbs, "-r", "relay.example.org"}
	if !slices.Equal(recordedExecArgs, expectedArgs) {
		t.Fatalf("expected recorded args %v, got %v", expectedArgs, recordedExecArgs)
	}
	if recordedExecRole != targetHbbs {
		t.Fatalf("expected role %q, got %q", targetHbbs, recordedExecRole)
	}
	if recordedExecAddr != "127.0.0.1:21116" {
		t.Fatalf("expected readiness addr 127.0.0.1:21116, got %q", recordedExecAddr)
	}

	if err := Run(ctx, nil, tempDir); err == nil {
		t.Fatal("expected error on missing command, got nil")
	}

	if err := Run(ctx, []string{targetHbbs}, filepath.Join(tempDir, "missing_secrets")); err == nil {
		t.Fatal("expected error on missing secrets dir, got nil")
	}

	execProcess = mockFailingExec
	if err := Run(ctx, []string{targetHbbs}, tempDir); err == nil {
		t.Fatal("expected execProcess failure, got nil")
	}
}

func TestMain_Execution(t *testing.T) {
	tempDir := t.TempDir()
	skBase64, pkBase64 := createTestEd25519Keypair()

	if err := os.WriteFile(filepath.Join(tempDir, fileIDEd25519), []byte(skBase64), 0o600); err != nil {
		t.Fatalf("writing sk: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, fileIDEd25519Pub), []byte(pkBase64), 0o600); err != nil {
		t.Fatalf("writing pk: %v", err)
	}

	origExit := exitFunc
	origExec := execProcess
	origReadDir := readDir
	origReadFile := readFile
	origArgs := os.Args

	exitFunc = mockExit
	execProcess = mockSuccessfulExec
	redirectedSecretsDir = tempDir
	readDir = mockRedirectedReadDir
	readFile = mockRedirectedReadFile

	t.Cleanup(func() {
		exitFunc = origExit
		execProcess = origExec
		readDir = origReadDir
		readFile = origReadFile
		os.Args = origArgs
	})

	recordedExitCode = -1
	os.Args = []string{"init", targetHbbr}
	main()

	if recordedExitCode != -1 {
		t.Fatalf("expected exit code -1 (success), got %d", recordedExitCode)
	}

	execProcess = mockFailingExec
	recordedExitCode = -1
	os.Args = []string{"init", targetHbbr}
	main()

	if recordedExitCode != 1 {
		t.Fatalf("expected exit code 1 on failure, got %d", recordedExitCode)
	}
}

func makeStatContent(comm, envStart, envEnd string, fieldCount int) string {
	var sb strings.Builder
	sb.WriteString("1234 (")
	sb.WriteString(comm)
	sb.WriteString(")")
	for i := range fieldCount {
		sb.WriteString(" ")
		switch i {
		case statEnvStartIndex:
			sb.WriteString(envStart)
		case statEnvEndIndex:
			sb.WriteString(envEnd)
		default:
			sb.WriteString("0")
		}
	}
	return sb.String()
}

func TestDefaultCloseFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "file.txt")
	file, err := os.Create(filepath.Clean(filePath))
	if err != nil {
		t.Fatalf("creating test file: %v", err)
	}

	if err := defaultCloseFile(file); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	if err := defaultCloseFile(file); err == nil {
		t.Fatal("expected error closing already closed file, got nil")
	}
}

func TestDefaultWriteMemory(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "mem.bin")
	cleanPath := filepath.Clean(filePath)
	file, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("creating test file: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("closing file: %v", closeErr)
		}
	}()

	n, err := defaultWriteMemory(file, []byte("payload"), 0)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 7 {
		t.Fatalf("expected 7 bytes written, got %d", n)
	}

	readOnlyFile, err := os.OpenFile(cleanPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("opening read-only file: %v", err)
	}
	defer func() {
		if closeErr := readOnlyFile.Close(); closeErr != nil {
			t.Errorf("closing read-only file: %v", closeErr)
		}
	}()

	if _, err := defaultWriteMemory(readOnlyFile, []byte("data"), 0); err == nil {
		t.Fatal("expected write error on read-only file, got nil")
	}
}

func TestDefaultOpenFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "open.txt")
	cleanPath := filepath.Clean(filePath)
	if err := os.WriteFile(cleanPath, []byte("data"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	file, err := defaultOpenFile(cleanPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("unexpected open error: %v", err)
	}
	if closeErr := file.Close(); closeErr != nil {
		t.Fatalf("closing file: %v", closeErr)
	}

	if _, err := defaultOpenFile(filepath.Join(tempDir, "missing.txt"), os.O_RDONLY, 0); err == nil {
		t.Fatal("expected error opening missing file, got nil")
	}
}

func TestDefaultCreateDialer(t *testing.T) {
	d := defaultCreateDialer()
	if d == nil {
		t.Fatal("expected non-nil dialer, got nil")
	}
}

func TestDefaultDialTCP(t *testing.T) {
	origDialer := createDialer
	createDialer = mockCreateDialer
	t.Cleanup(func() { createDialer = origDialer })

	activeMockDialer.err = errMockDial
	activeMockDialer.conn = nil
	if _, err := defaultDialTCP(context.Background(), "tcp", "127.0.0.1:29998"); err == nil {
		t.Fatal("expected dial error, got nil")
	}

	activeMockDialer.err = nil
	activeMockDialer.conn = &mockSuccessConn{}
	conn, err := defaultDialTCP(context.Background(), "tcp", "127.0.0.1:29998")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn, got nil")
	}
}

func TestDefaultProcPath(t *testing.T) {
	got := defaultProcPath(42, "stat")
	expected := filepath.Join(defaultProcDir, "42", "stat")
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestParseProcStat(t *testing.T) {
	tests := []struct {
		name         string
		statContent  string
		wantEnvStart int64
		wantEnvEnd   int64
		expectErr    bool
	}{
		{
			name:        "missing_closing_comm_paren",
			statContent: "1234 hbbs 0 0 0",
			expectErr:   true,
		},
		{
			name:        "insufficient_fields_after_comm",
			statContent: makeStatContent("hbbs", "100", "200", 20),
			expectErr:   true,
		},
		{
			name:        "invalid_env_start_non_number",
			statContent: makeStatContent("hbbs", "not_a_number", "200", 49),
			expectErr:   true,
		},
		{
			name:        "invalid_env_end_non_number",
			statContent: makeStatContent("hbbs", "100", "not_a_number", 49),
			expectErr:   true,
		},
		{
			name:        "negative_or_zero_env_start",
			statContent: makeStatContent("hbbs", "0", "200", 49),
			expectErr:   true,
		},
		{
			name:        "env_start_greater_than_env_end",
			statContent: makeStatContent("hbbs", "300", "200", 49),
			expectErr:   true,
		},
		{
			name:        "env_range_exceeds_max_limit",
			statContent: makeStatContent("hbbs", "1000", "34554433", 49),
			expectErr:   true,
		},
		{
			name:         "valid_stat_with_nested_comm",
			statContent:  makeStatContent("hbbs (worker) proc", "1000", "2000", 49),
			wantEnvStart: 1000,
			wantEnvEnd:   2000,
			expectErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envStart, envEnd, err := parseProcStat(tt.statContent)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for case %q, got nil", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for case %q: %v", tt.name, err)
			}
			if envStart != tt.wantEnvStart || envEnd != tt.wantEnvEnd {
				t.Fatalf("expected (%d, %d), got (%d, %d)", tt.wantEnvStart, tt.wantEnvEnd, envStart, envEnd)
			}
		})
	}
}

func TestWaitForChildReadiness(t *testing.T) {
	origDial := dialTCP
	t.Cleanup(func() { dialTCP = origDial })

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForChildReadiness(canceledCtx, "127.0.0.1:29990", time.Second); err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}

	dialTCP = mockSuccessDialTCP
	if err := waitForChildReadiness(context.Background(), "127.0.0.1:29990", time.Second); err != nil {
		t.Fatalf("unexpected error on ready socket: %v", err)
	}

	dialTCP = mockErrorCloserDialTCP
	if err := waitForChildReadiness(context.Background(), "127.0.0.1:29990", time.Second); err == nil {
		t.Fatal("expected error when socket close fails, got nil")
	}

	dialTCP = mockFailingDialTCP
	if err := waitForChildReadiness(context.Background(), "127.0.0.1:29990", -1*time.Second); err != nil {
		t.Fatalf("expected nil when deadline passed, got %v", err)
	}

	ctxWait, cancelWait := context.WithCancel(context.Background())
	time.AfterFunc(2*time.Millisecond, cancelWait)
	if err := waitForChildReadiness(ctxWait, "127.0.0.1:29990", 2*time.Second); err == nil {
		t.Fatal("expected error when context canceled during wait, got nil")
	}

	mockDialAttemptCount = 0
	dialTCP = mockRetrySuccessDialTCP
	if err := waitForChildReadiness(context.Background(), "127.0.0.1:29990", time.Second); err != nil {
		t.Fatalf("unexpected error on retry dial: %v", err)
	}
}

func setupScrubChildFixture(t *testing.T) (pid int, statPath, memPath string) {
	t.Helper()
	tempDir := t.TempDir()
	pid = 4242
	pidDir := filepath.Join(tempDir, strconv.Itoa(pid))
	if err := os.Mkdir(pidDir, 0o750); err != nil {
		t.Fatalf("creating pid dir: %v", err)
	}

	statFilePath := filepath.Join(pidDir, "stat")
	memFilePath := filepath.Join(pidDir, "mem")

	validStatData := makeStatContent("hbbs", "10", "20", 49)
	if err := os.WriteFile(filepath.Clean(statFilePath), []byte(validStatData), 0o600); err != nil {
		t.Fatalf("writing stat file: %v", err)
	}

	initialMem := make([]byte, 30)
	for i := range initialMem {
		initialMem[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Clean(memFilePath), initialMem, 0o600); err != nil {
		t.Fatalf("writing mem file: %v", err)
	}

	mockProcDirectory = tempDir
	procPath = mockProcPath
	return pid, statFilePath, memFilePath
}

func setupScrubCleanup(t *testing.T) {
	t.Helper()
	origProcPath := procPath
	origReadFile := readFile
	origOpenFile := openFile
	origWriteMem := writeMemory
	origCloseFile := closeFile
	origDialTCP := dialTCP

	dialTCP = mockSuccessDialTCP

	t.Cleanup(func() {
		procPath = origProcPath
		readFile = origReadFile
		openFile = origOpenFile
		writeMemory = origWriteMem
		closeFile = origCloseFile
		dialTCP = origDialTCP
		mockProcDirectory = ""
	})
}

func TestDefaultScrubChildMemory_ReadinessErrors(t *testing.T) {
	setupScrubCleanup(t)
	pid, _, _ := setupScrubChildFixture(t)

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := defaultScrubChildMemory(canceledCtx, pid, "127.0.0.1:29989"); err != nil {
		t.Fatalf("expected nil when readiness context canceled, got %v", err)
	}

	dialTCP = mockErrorCloserDialTCP
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29989"); err == nil {
		t.Fatal("expected error on readiness failure, got nil")
	}
}

func TestDefaultScrubChildMemory_ReadAndParseErrors(t *testing.T) {
	setupScrubCleanup(t)
	pid, statFilePath, _ := setupScrubChildFixture(t)

	if err := defaultScrubChildMemory(context.Background(), 9999, "127.0.0.1:29988"); err != nil {
		t.Fatalf("expected nil when stat file missing, got %v", err)
	}

	readFile = mockPermissionReadFile
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29988"); err != nil {
		t.Fatalf("expected nil on stat read permission error, got %v", err)
	}

	readFile = mockFailingReadFile
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29988"); err == nil {
		t.Fatal("expected error on generic stat read error, got nil")
	}
	readFile = defaultReadFile

	if err := os.WriteFile(filepath.Clean(statFilePath), []byte("corrupt stat data"), 0o600); err != nil {
		t.Fatalf("overwriting stat: %v", err)
	}
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29988"); err == nil {
		t.Fatal("expected error on corrupt stat data, got nil")
	}
}

func TestDefaultScrubChildMemory_OpenErrors(t *testing.T) {
	setupScrubCleanup(t)
	pid, _, memFilePath := setupScrubChildFixture(t)

	if err := os.Remove(filepath.Clean(memFilePath)); err != nil {
		t.Fatalf("removing mem file: %v", err)
	}
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29987"); err != nil {
		t.Fatalf("expected nil when mem file missing, got %v", err)
	}

	openFile = mockPermissionOpenFile
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29987"); err != nil {
		t.Fatalf("expected nil on mem open permission error, got %v", err)
	}

	openFile = mockFailingOpenFile
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29987"); err == nil {
		t.Fatal("expected error on generic mem open error, got nil")
	}
}

func TestDefaultScrubChildMemory_WriteErrors(t *testing.T) {
	setupScrubCleanup(t)
	pid, _, _ := setupScrubChildFixture(t)

	writeMemory = mockPermissionWriteMemory
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29986"); err != nil {
		t.Fatalf("expected nil on mem write permission error, got %v", err)
	}

	writeMemory = mockFailingWriteMemory
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29986"); err == nil {
		t.Fatal("expected error on generic mem write error, got nil")
	}
}

func TestDefaultScrubChildMemory_CloseErrors(t *testing.T) {
	setupScrubCleanup(t)
	pid, _, _ := setupScrubChildFixture(t)

	closeFile = mockPermissionCloseFile
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29985"); err != nil {
		t.Fatalf("expected nil on mem close permission error, got %v", err)
	}

	closeFile = mockFailingCloseFile
	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29985"); err == nil {
		t.Fatal("expected error on generic mem close error, got nil")
	}
}

func TestDefaultScrubChildMemory_Success(t *testing.T) {
	setupScrubCleanup(t)
	pid, _, memFilePath := setupScrubChildFixture(t)

	if err := defaultScrubChildMemory(context.Background(), pid, "127.0.0.1:29984"); err != nil {
		t.Fatalf("unexpected error on successful scrub: %v", err)
	}

	scrubbedData, err := os.ReadFile(filepath.Clean(memFilePath))
	if err != nil {
		t.Fatalf("reading scrubbed mem file: %v", err)
	}
	for i := range 10 {
		if scrubbedData[i] != byte(i+1) {
			t.Fatalf("expected untouched byte at %d, got %d", i, scrubbedData[i])
		}
	}
	for i := 10; i < 20; i++ {
		if scrubbedData[i] != 0 {
			t.Fatalf("expected zeroed byte at %d, got %d", i, scrubbedData[i])
		}
	}
	for i := 20; i < 30; i++ {
		if scrubbedData[i] != byte(i+1) {
			t.Fatalf("expected untouched byte at %d, got %d", i, scrubbedData[i])
		}
	}
}

func TestRunKeygen_Success(t *testing.T) {
	tempDir := t.TempDir()
	outDir := filepath.Join(tempDir, "keys")

	if err := runKeygen(outDir); err != nil {
		t.Fatalf("runKeygen failed unexpectedly: %v", err)
	}

	skRaw, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, fileIDEd25519)))
	if err != nil {
		t.Fatalf("reading generated private key: %v", err)
	}

	pkRaw, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, fileIDEd25519Pub)))
	if err != nil {
		t.Fatalf("reading generated public key: %v", err)
	}

	skTrimmed := strings.TrimSpace(string(skRaw))
	pkTrimmed := strings.TrimSpace(string(pkRaw))

	skBytes, err := base64.StdEncoding.DecodeString(skTrimmed)
	if err != nil {
		t.Fatalf("decoding private key base64: %v", err)
	}
	if len(skBytes) != ed25519SecretKeyBytes {
		t.Fatalf("expected sk length %d, got %d", ed25519SecretKeyBytes, len(skBytes))
	}

	pkBytes, err := base64.StdEncoding.DecodeString(pkTrimmed)
	if err != nil {
		t.Fatalf("decoding public key base64: %v", err)
	}
	if len(pkBytes) != ed25519PublicKeyBytes {
		t.Fatalf("expected pk length %d, got %d", ed25519PublicKeyBytes, len(pkBytes))
	}

	derivedPk := skBytes[ed25519PublicKeyBytes:ed25519SecretKeyBytes]
	if !bytes.Equal(derivedPk, pkBytes) {
		t.Fatalf("expected derived public key %x to match %x", derivedPk, pkBytes)
	}
}

func TestRunKeygen_Errors(t *testing.T) {
	origMkdir := mkdirAll
	origGenerate := generateKey
	origWrite := writeFile
	t.Cleanup(func() {
		mkdirAll = origMkdir
		generateKey = origGenerate
		writeFile = origWrite
		mockFailWriteTarget = ""
	})

	tests := []struct {
		setup     func()
		name      string
		expectErr bool
	}{
		{
			setup: func() {
				mkdirAll = mockFailingMkdirAll
			},
			name:      "mkdir_failure",
			expectErr: true,
		},
		{
			setup: func() {
				generateKey = mockFailingGenerateKey
			},
			name:      "generate_key_failure",
			expectErr: true,
		},
		{
			setup: func() {
				writeFile = mockFailingWriteFile
			},
			name:      "write_private_key_failure",
			expectErr: true,
		},
		{
			setup: func() {
				mockFailWriteTarget = fileIDEd25519Pub
				writeFile = mockConditionalWriteFile
			},
			name:      "write_public_key_failure",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mkdirAll = origMkdir
			generateKey = origGenerate
			writeFile = origWrite
			mockFailWriteTarget = ""

			tt.setup()
			err := runKeygen(t.TempDir())
			if tt.expectErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestGenerateKeys(t *testing.T) {
	tempDir := t.TempDir()
	if err := GenerateKeys(tempDir); err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}
}

func TestRun_Keygen(t *testing.T) {
	tempDir := t.TempDir()
	origKeygenDir := keygenDir
	keygenDir = tempDir
	t.Cleanup(func() { keygenDir = origKeygenDir })

	if err := Run(context.Background(), []string{targetKeygen}, defaultSecretsDir); err != nil {
		t.Fatalf("Run keygen failed: %v", err)
	}

	if err := Run(context.Background(), []string{targetKeygen, "unexpected_arg"}, defaultSecretsDir); err == nil {
		t.Fatal("expected error passing extra arguments to keygen, got nil")
	}
}

func TestDefaultKeygenHelpers_Success(t *testing.T) {
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "test_dir")
	if err := defaultMkdirAll(testDir, 0o750); err != nil {
		t.Fatalf("defaultMkdirAll failed: %v", err)
	}

	testFile := filepath.Join(testDir, "test.txt")
	testData := []byte("hello")
	if err := defaultWriteFile(testFile, testData, 0o440); err != nil {
		t.Fatalf("defaultWriteFile failed: %v", err)
	}

	pub, priv, err := defaultGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("defaultGenerateKey failed: %v", err)
	}
	if len(pub) != ed25519PublicKeyBytes || len(priv) != ed25519SecretKeyBytes {
		t.Fatalf("unexpected key lengths: pub=%d priv=%d", len(pub), len(priv))
	}
}

func TestDefaultKeygenHelpers_Errors(t *testing.T) {
	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "test_dir")
	if err := defaultMkdirAll(testDir, 0o750); err != nil {
		t.Fatalf("defaultMkdirAll failed: %v", err)
	}

	testFile := filepath.Join(testDir, "test.txt")
	testData := []byte("hello")
	if err := defaultWriteFile(testFile, testData, 0o440); err != nil {
		t.Fatalf("defaultWriteFile failed: %v", err)
	}

	if err := defaultMkdirAll(filepath.Clean(filepath.Join(testFile, "nested")), 0o750); err == nil {
		t.Fatal("expected error creating directory inside file in defaultMkdirAll, got nil")
	}

	if err := defaultWriteFile(testDir, testData, 0o440); err == nil {
		t.Fatal("expected error writing to directory path in defaultWriteFile, got nil")
	}

	if _, _, err := defaultGenerateKey(mockFailingReader{}); err == nil {
		t.Fatal("expected error from defaultGenerateKey with failing reader, got nil")
	}
}
