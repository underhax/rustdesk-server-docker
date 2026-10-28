// Package main implements a lightweight TCP liveness probe for RustDesk hbbs and hbbr services.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	targetHbbr = "hbbr"
	targetHbbs = "hbbs"

	defaultHbbrPort  = "21117"
	defaultHbbsPort1 = "21115"
	defaultHbbsPort2 = "21116"

	defaultLoopback = "127.0.0.1"
	probeEnvVar     = "RUSTDESK_PROBE_ADDR"
	defaultTimeout  = 2 * time.Second
)

var (
	errUnknownTarget    = errors.New("unknown probe target role")
	errMissingTarget    = errors.New("missing probe target role")
	errEmptyAddressList = errors.New("empty probe target address list")
)

type socketDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func defaultCreateDialer(timeout time.Duration) socketDialer {
	return &net.Dialer{Timeout: timeout}
}

var (
	createDialer = defaultCreateDialer
	exitFunc     = os.Exit
)

func defaultDial(ctx context.Context, addr string, timeout time.Duration) error {
	dialer := createDialer(timeout)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dialing %s: %w", addr, err)
	}
	if closeErr := conn.Close(); closeErr != nil {
		return fmt.Errorf("closing socket %s: %w", addr, closeErr)
	}
	return nil
}

var dialAddr = defaultDial

// ResolveAddresses determines the list of TCP endpoints to interrogate based on either
// an explicit environment override or the defined service role to verify listener availability.
func ResolveAddresses(target, envOverride string) ([]string, error) {
	if trimmed := strings.TrimSpace(envOverride); trimmed != "" {
		parts := strings.Split(trimmed, ",")
		res := make([]string, 0, len(parts))
		for _, part := range parts {
			clean := strings.TrimSpace(part)
			if clean != "" {
				res = append(res, clean)
			}
		}
		if len(res) == 0 {
			return nil, errEmptyAddressList
		}
		return res, nil
	}

	cleanTarget := strings.TrimSpace(target)
	switch cleanTarget {
	case targetHbbr:
		return []string{net.JoinHostPort(defaultLoopback, defaultHbbrPort)}, nil
	case targetHbbs:
		return []string{
			net.JoinHostPort(defaultLoopback, defaultHbbsPort1),
			net.JoinHostPort(defaultLoopback, defaultHbbsPort2),
		}, nil
	case "":
		return nil, errMissingTarget
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownTarget, cleanTarget)
	}
}

// CheckAddresses establishes TCP connections to each target address within the allocated deadline
// to confirm operational readiness of container network daemons.
func CheckAddresses(ctx context.Context, addresses []string, timeout time.Duration) error {
	if len(addresses) == 0 {
		return errEmptyAddressList
	}
	for _, addr := range addresses {
		if err := dialAddr(ctx, addr, timeout); err != nil {
			return err
		}
	}
	return nil
}

// Run orchestrates argument parsing, target discovery, and socket probing to signal container
// health to the container runtime via process exit code.
func Run(ctx context.Context, args []string, envVal string) int {
	var target string
	if len(args) > 0 {
		target = args[0]
	}

	addrs, err := ResolveAddresses(target, envVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe configuration error: %v\n", err)
		return 1
	}

	if err := CheckAddresses(ctx, addrs, defaultTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "probe health check failed: %v\n", err)
		return 1
	}

	return 0
}

func main() {
	var args []string
	if len(os.Args) > 1 {
		args = os.Args[1:]
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	exitFunc(Run(ctx, args, os.Getenv(probeEnvVar)))
}
