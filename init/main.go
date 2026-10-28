// Package main initializes the RustDesk container runtime environment by injecting
// Docker secrets, enforcing immutable security parameters, and executing hbbs or hbbr daemons.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	targetHbbs   = "hbbs"
	targetHbbr   = "hbbr"
	targetKeygen = "keygen"

	defaultHbbsBinaryPath = "/usr/local/bin/hbbs"
	defaultHbbrBinaryPath = "/usr/local/bin/hbbr"
	defaultSecretsDir     = "/run/secrets"
	defaultKeygenDir      = "/secrets"
)

const (
	fileIDEd25519    = "id_ed25519"
	fileIDEd25519Pub = "id_ed25519.pub"
)

const (
	envKey           = "KEY"
	envEncryptedOnly = "ENCRYPTED_ONLY"
	envSSLCertFile   = "SSL_CERT_FILE"
	envSSLCertDir    = "SSL_CERT_DIR"
	envHome          = "HOME"
)

const (
	defaultHbbsPort         = "21116"
	defaultHbbrPort         = "21117"
	defaultLoopbackAddress  = "127.0.0.1"
	defaultProcDir          = "/proc"
	defaultSSLCertFile      = "/etc/ssl/certs/ca-certificates.crt"
	defaultSSLCertDir       = "/etc/ssl/certs"
	defaultHomeDir          = "/tmp"
	defaultReadinessTimeout = 30 * time.Second
	childReadinessInterval  = 50 * time.Millisecond
	maxEnvRangeSize         = 32 * 1024 * 1024
	minStatFieldsAfterComm  = 49
	statEnvStartIndex       = 47
	statEnvEndIndex         = 48
	ed25519PublicKeyBytes   = 32
	ed25519SecretKeyBytes   = 64
)

const (
	rustdeskSecretPrefix = "rd_"
)

var (
	errKeyMismatch     = errors.New("public key does not match ed25519 secret key")
	errInvalidKeySize  = errors.New("invalid cryptographic key byte size")
	errUnknownCommand  = errors.New("unsupported service command")
	errMissingCommand  = errors.New("missing service command argument")
	errEmptySecretName = errors.New("secret name cannot be empty")
	errUnexpectedArgs  = errors.New("unexpected command arguments")
)

func defaultGenerateKey(randReader io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	return pub, priv, nil
}

func defaultWriteFile(name string, data []byte, perm os.FileMode) error {
	cleanPath := filepath.Clean(name)
	if err := os.WriteFile(cleanPath, data, perm); err != nil {
		return fmt.Errorf("writing file %q: %w", cleanPath, err)
	}
	return nil
}

func defaultMkdirAll(path string, perm os.FileMode) error {
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(cleanPath, perm); err != nil {
		return fmt.Errorf("creating directory %q: %w", cleanPath, err)
	}
	return nil
}

func defaultReadFile(path string) ([]byte, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("reading file %q: %w", cleanPath, err)
	}
	return data, nil
}

func defaultReadDir(dirname string) ([]fs.DirEntry, error) {
	cleanDir := filepath.Clean(dirname)
	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %q: %w", cleanDir, err)
	}
	return entries, nil
}

func defaultCloseFile(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing file: %w", err)
	}
	return nil
}

func defaultWriteMemory(f *os.File, b []byte, off int64) (int, error) {
	n, err := f.WriteAt(b, off)
	if err != nil {
		return n, fmt.Errorf("writing memory: %w", err)
	}
	return n, nil
}

func defaultOpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	cleanPath := filepath.Clean(name)
	file, err := os.OpenFile(cleanPath, flag, perm)
	if err != nil {
		return nil, fmt.Errorf("opening file %q: %w", cleanPath, err)
	}
	return file, nil
}

type socketDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func defaultCreateDialer() socketDialer {
	return &net.Dialer{}
}

func defaultDialTCP(ctx context.Context, network, address string) (net.Conn, error) {
	d := createDialer()
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dialing %s %s: %w", network, address, err)
	}
	return conn, nil
}

func defaultProcPath(pid int, entry string) string {
	return filepath.Join(defaultProcDir, strconv.Itoa(pid), entry)
}

func cancelCommand(cmd *exec.Cmd) func() error {
	return func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}
}

func defaultCreateCommand(ctx context.Context, role string, args []string) *exec.Cmd {
	targetPath := defaultHbbsBinaryPath
	if role == targetHbbr {
		targetPath = defaultHbbrBinaryPath
	}
	cmd := exec.CommandContext(ctx, targetPath)
	if len(args) > 1 {
		cmd.Args = append([]string{targetPath}, args[1:]...)
	}
	cmd.Cancel = cancelCommand(cmd)
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func parseProcStat(statContent string) (envStart, envEnd int64, err error) {
	_, remainder, found := strings.CutLast(statContent, ")")
	if !found {
		return 0, 0, errors.New("missing closing parenthesis for comm in stat content")
	}

	fields := strings.Fields(remainder)
	if len(fields) < minStatFieldsAfterComm {
		return 0, 0, fmt.Errorf("stat fields count %d below required minimum %d", len(fields), minStatFieldsAfterComm)
	}

	envStart, err = strconv.ParseInt(fields[statEnvStartIndex], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing env_start from stat: %w", err)
	}

	envEnd, err = strconv.ParseInt(fields[statEnvEndIndex], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing env_end from stat: %w", err)
	}

	if envStart <= 0 || envEnd <= envStart {
		return 0, 0, fmt.Errorf("invalid environment boundaries: env_start (%d) >= env_end (%d)", envStart, envEnd)
	}

	if envEnd-envStart > maxEnvRangeSize {
		return 0, 0, fmt.Errorf("environment range size %d exceeds limit of %d bytes", envEnd-envStart, maxEnvRangeSize)
	}

	return envStart, envEnd, nil
}

func waitForChildReadiness(ctx context.Context, addr string, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("readiness context canceled: %w", err)
		}
		conn, err := dialTCP(waitCtx, "tcp", addr)
		if err == nil {
			if closeErr := conn.Close(); closeErr != nil {
				return fmt.Errorf("closing readiness socket: %w", closeErr)
			}
			return nil
		}
		timer := time.NewTimer(childReadinessInterval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("readiness context canceled: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func isIgnorableMemoryError(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission)
}

func defaultScrubChildMemory(ctx context.Context, pid int, targetAddr string) (err error) {
	if readinessErr := waitForChildReadiness(ctx, targetAddr, defaultReadinessTimeout); readinessErr != nil {
		if isIgnorableMemoryError(readinessErr) || errors.Is(readinessErr, context.Canceled) {
			return nil
		}
		return fmt.Errorf("synchronizing child readiness: %w", readinessErr)
	}

	statPath := procPath(pid, "stat")
	statBytes, readErr := readFile(statPath)
	if readErr != nil {
		if isIgnorableMemoryError(readErr) {
			return nil
		}
		return fmt.Errorf("reading stat file %q: %w", statPath, readErr)
	}

	envStart, envEnd, parseErr := parseProcStat(string(statBytes))
	if parseErr != nil {
		return fmt.Errorf("parsing stat file %q: %w", statPath, parseErr)
	}

	memPath := procPath(pid, "mem")
	memFile, openErr := openFile(memPath, os.O_RDWR, 0)
	if openErr != nil {
		if isIgnorableMemoryError(openErr) {
			return nil
		}
		return fmt.Errorf("opening mem file %q: %w", memPath, openErr)
	}
	defer func() {
		if closeErr := closeFile(memFile); closeErr != nil && err == nil && !isIgnorableMemoryError(closeErr) {
			err = fmt.Errorf("closing mem file %q: %w", memPath, closeErr)
		}
	}()

	zeros := make([]byte, envEnd-envStart)
	if _, writeErr := writeMemory(memFile, zeros, envStart); writeErr != nil {
		if isIgnorableMemoryError(writeErr) {
			return nil
		}
		return fmt.Errorf("zeroing memory in %q: %w", memPath, writeErr)
	}

	return nil
}

func defaultExec(ctx context.Context, role string, args, env []string, readinessAddr string) error {
	cmd := createCommand(ctx, role, args)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", role, err)
	}

	pid := cmd.Process.Pid
	scrubCtx, cancelScrub := context.WithCancel(ctx)
	defer cancelScrub()

	scrubDone := make(chan struct{})
	go func() {
		defer close(scrubDone)
		if scrubErr := scrubChildMemory(scrubCtx, pid, readinessAddr); scrubErr != nil {
			fmt.Fprintf(os.Stderr, "memory scrubbing failed: %v\n", scrubErr)
		}
	}()

	cmd.Env = nil
	clear(env)
	runtime.GC()

	waitErr := cmd.Wait()
	cancelScrub()
	<-scrubDone

	if waitErr != nil {
		return fmt.Errorf("running %s: %w", role, waitErr)
	}
	return nil
}

var (
	closeFile        = defaultCloseFile
	createCommand    = defaultCreateCommand
	createDialer     = defaultCreateDialer
	dialTCP          = defaultDialTCP
	execProcess      = defaultExec
	exitFunc         = os.Exit
	generateKey      = defaultGenerateKey
	keygenDir        = defaultKeygenDir
	mkdirAll         = defaultMkdirAll
	openFile         = defaultOpenFile
	procPath         = defaultProcPath
	readDir          = defaultReadDir
	readFile         = defaultReadFile
	scrubChildMemory = defaultScrubChildMemory
	writeFile        = defaultWriteFile
	writeMemory      = defaultWriteMemory
)

func readOptionalSecret(path string) (secret string, exists bool, err error) {
	data, err := readFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading secret %q: %w", path, err)
	}

	trimmed := strings.TrimSpace(string(data))
	clear(data)
	return trimmed, true, nil
}

func readRequiredSecret(secretsDir, secretName string) (string, error) {
	path := filepath.Join(secretsDir, secretName)
	val, exists, err := readOptionalSecret(path)
	if err != nil {
		return "", err
	}
	if !exists || val == "" {
		return "", fmt.Errorf("required secret %q is missing or empty", secretName)
	}
	return val, nil
}

func setEnvVar(env []string, key, value string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func listSecretNames(secretsDir string) ([]string, error) {
	entries, err := readDir(secretsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("scanning secrets directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}

	slices.Sort(names)
	return names, nil
}

func hasRustdeskSecretPrefix(name string) bool {
	return len(name) >= len(rustdeskSecretPrefix) && strings.EqualFold(name[:len(rustdeskSecretPrefix)], rustdeskSecretPrefix)
}

func isInvalidEnvKeyRune(r rune) bool {
	return (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-'
}

func secretEnvKey(name string) (string, error) {
	if len(name) < len(rustdeskSecretPrefix) {
		return "", errEmptySecretName
	}
	remainder := name[len(rustdeskSecretPrefix):]
	key := strings.ToUpper(remainder)
	if key == "" || strings.ContainsFunc(key, isInvalidEnvKeyRune) {
		return "", fmt.Errorf("secret %q cannot be mapped to an environment variable", name)
	}
	return key, nil
}

func decodeBase64Key(raw string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 key: %w", err)
		}
	}
	return decoded, nil
}

func configureDynamicSecrets(env []string, secretsDir string, names []string) ([]string, error) {
	for _, name := range names {
		if !hasRustdeskSecretPrefix(name) {
			continue
		}

		key, err := secretEnvKey(name)
		if err != nil {
			return nil, err
		}

		val, exists, err := readOptionalSecret(filepath.Join(secretsDir, name))
		if err != nil {
			return nil, err
		}
		if exists && val != "" {
			env = setEnvVar(env, key, val)
		}
	}
	return env, nil
}

func configureHbbsKeySecrets(env []string, secretsDir string) ([]string, error) {
	skBase64, err := readRequiredSecret(secretsDir, fileIDEd25519)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", fileIDEd25519, err)
	}

	pkBase64, err := readRequiredSecret(secretsDir, fileIDEd25519Pub)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", fileIDEd25519Pub, err)
	}

	skBytes, err := decodeBase64Key(skBase64)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", fileIDEd25519, err)
	}
	defer clear(skBytes)

	if len(skBytes) != ed25519SecretKeyBytes {
		return nil, fmt.Errorf("%w: secret key length %d expected %d", errInvalidKeySize, len(skBytes), ed25519SecretKeyBytes)
	}

	pkBytes, err := decodeBase64Key(pkBase64)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", fileIDEd25519Pub, err)
	}
	defer clear(pkBytes)

	if len(pkBytes) != ed25519PublicKeyBytes {
		return nil, fmt.Errorf("%w: public key length %d expected %d", errInvalidKeySize, len(pkBytes), ed25519PublicKeyBytes)
	}

	derivedPk := skBytes[ed25519PublicKeyBytes:ed25519SecretKeyBytes]
	if !bytes.Equal(derivedPk, pkBytes) {
		return nil, errKeyMismatch
	}

	env = setEnvVar(env, envKey, skBase64)
	env = setEnvVar(env, envEncryptedOnly, "1")
	return env, nil
}

func configureHbbrKeySecrets(env []string, secretsDir string) ([]string, error) {
	pkBase64, err := readRequiredSecret(secretsDir, fileIDEd25519Pub)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", fileIDEd25519Pub, err)
	}

	pkBytes, err := decodeBase64Key(pkBase64)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", fileIDEd25519Pub, err)
	}
	defer clear(pkBytes)

	if len(pkBytes) != ed25519PublicKeyBytes {
		return nil, fmt.Errorf("%w: public key length %d expected %d", errInvalidKeySize, len(pkBytes), ed25519PublicKeyBytes)
	}

	env = setEnvVar(env, envKey, pkBase64)
	return env, nil
}

func configureEnforcedSettings(env []string) []string {
	env = setEnvVar(env, envSSLCertFile, defaultSSLCertFile)
	env = setEnvVar(env, envSSLCertDir, defaultSSLCertDir)
	env = setEnvVar(env, envHome, defaultHomeDir)
	return env
}

// ResolveTargetCommand validates invocation parameters and returns target binary paths
// and normalized service arguments to enforce deterministic process dispatching.
func ResolveTargetCommand(args []string) (binaryPath, role string, cmdArgs []string, err error) {
	if len(args) == 0 {
		return "", "", nil, errMissingCommand
	}

	target := args[0]
	switch target {
	case targetHbbs, defaultHbbsBinaryPath:
		cmdArgs = append([]string{targetHbbs}, args[1:]...)
		return defaultHbbsBinaryPath, targetHbbs, cmdArgs, nil
	case targetHbbr, defaultHbbrBinaryPath:
		cmdArgs = append([]string{targetHbbr}, args[1:]...)
		return defaultHbbrBinaryPath, targetHbbr, cmdArgs, nil
	default:
		return "", "", nil, fmt.Errorf("%w: %q", errUnknownCommand, target)
	}
}

func resolveReadinessAddress(role string) string {
	if role == targetHbbr {
		return net.JoinHostPort(defaultLoopbackAddress, defaultHbbrPort)
	}
	return net.JoinHostPort(defaultLoopbackAddress, defaultHbbsPort)
}

// PrepareEnvironment populates process configuration from Docker secrets and enforces
// immutable container constraints required for secure scratch execution.
func PrepareEnvironment(baseEnv []string, secretsDir, role string) ([]string, error) {
	env := slices.Clone(baseEnv)

	names, err := listSecretNames(secretsDir)
	if err != nil {
		return nil, err
	}

	if env, err = configureDynamicSecrets(env, secretsDir, names); err != nil {
		return nil, err
	}

	switch role {
	case targetHbbs:
		if env, err = configureHbbsKeySecrets(env, secretsDir); err != nil {
			return nil, err
		}
	case targetHbbr:
		if env, err = configureHbbrKeySecrets(env, secretsDir); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownCommand, role)
	}

	env = configureEnforcedSettings(env)
	return env, nil
}

func runKeygen(targetDir string) error {
	cleanDir := filepath.Clean(targetDir)
	if err := mkdirAll(cleanDir, 0o750); err != nil {
		return fmt.Errorf("creating target directory: %w", err)
	}

	pub, priv, err := generateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating ed25519 keypair: %w", err)
	}

	skB64 := base64.StdEncoding.EncodeToString(priv)
	pkB64 := base64.StdEncoding.EncodeToString(pub)

	privPath := filepath.Join(cleanDir, fileIDEd25519)
	if err := writeFile(privPath, []byte(skB64+"\n"), 0o440); err != nil {
		return fmt.Errorf("saving %s: %w", fileIDEd25519, err)
	}

	pubPath := filepath.Join(cleanDir, fileIDEd25519Pub)
	if err := writeFile(pubPath, []byte(pkB64+"\n"), 0o440); err != nil {
		return fmt.Errorf("saving %s: %w", fileIDEd25519Pub, err)
	}

	fmt.Printf("Public key (%s): %s\n", fileIDEd25519Pub, pkB64)
	return nil
}

// GenerateKeys generates a canonical Ed25519 keypair and writes encoded secret files
// to the target directory to facilitate automated provisioning of container secrets.
func GenerateKeys(targetDir string) error {
	return runKeygen(targetDir)
}

// Run coordinates environment preparation, command dispatching, key generation, and process
// supervision to ensure graceful shutdown and memory-scrubbed secret injection during container execution.
func Run(ctx context.Context, args []string, secretsDir string) error {
	if len(args) > 0 && args[0] == targetKeygen {
		if len(args) > 1 {
			return fmt.Errorf("%w: %q does not accept arguments", errUnexpectedArgs, targetKeygen)
		}
		return runKeygen(keygenDir)
	}

	_, role, cmdArgs, err := ResolveTargetCommand(args)
	if err != nil {
		return fmt.Errorf("resolving target command: %w", err)
	}

	env, err := PrepareEnvironment(os.Environ(), secretsDir, role)
	if err != nil {
		return fmt.Errorf("preparing runtime environment: %w", err)
	}

	readinessAddr := resolveReadinessAddress(role)
	if execErr := execProcess(ctx, role, cmdArgs, env, readinessAddr); execErr != nil {
		return fmt.Errorf("executing %s: %w", role, execErr)
	}

	return nil
}

func main() {
	var args []string
	if len(os.Args) > 1 {
		args = os.Args[1:]
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := Run(ctx, args, defaultSecretsDir); err != nil {
		fmt.Fprintf(os.Stderr, "init error: %v\n", err)
		exitFunc(1)
	}
}
