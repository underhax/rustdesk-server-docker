package main

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"testing"
	"time"
)

var (
	errMockDial  = errors.New("simulated dial failure")
	errMockClose = errors.New("simulated close failure")
)

type mockSuccessConn struct {
	net.Conn
}

func (m *mockSuccessConn) Close() error {
	return nil
}

type mockFailingCloseConn struct {
	net.Conn
}

func (m *mockFailingCloseConn) Close() error {
	return errMockClose
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

func mockCreateDialer(_ time.Duration) socketDialer {
	return activeMockDialer
}

var recordedExitCode = -1

func mockExit(code int) {
	recordedExitCode = code
}

func defaultMockDial(_ context.Context, _ string, _ time.Duration) error {
	return nil
}

func failingMockDial(_ context.Context, _ string, _ time.Duration) error {
	return errMockDial
}

func TestResolveAddresses(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		envOverride string
		want        []string
		expectErr   bool
	}{
		{
			name:        "hbbr_target_success",
			target:      targetHbbr,
			envOverride: "",
			want:        []string{"127.0.0.1:21117"},
			expectErr:   false,
		},
		{
			name:        "hbbs_target_success",
			target:      targetHbbs,
			envOverride: "",
			want:        []string{"127.0.0.1:21115", "127.0.0.1:21116"},
			expectErr:   false,
		},
		{
			name:        "env_override_single",
			target:      targetHbbs,
			envOverride: "127.0.0.1:29999",
			want:        []string{"127.0.0.1:29999"},
			expectErr:   false,
		},
		{
			name:        "env_override_multiple_with_spaces",
			target:      "",
			envOverride: " 127.0.0.1:29991 , 127.0.0.1:29992 ",
			want:        []string{"127.0.0.1:29991", "127.0.0.1:29992"},
			expectErr:   false,
		},
		{
			name:        "env_override_empty_commas",
			target:      targetHbbr,
			envOverride: "  ,  ",
			want:        nil,
			expectErr:   true,
		},
		{
			name:        "missing_target_empty",
			target:      "   ",
			envOverride: "",
			want:        nil,
			expectErr:   true,
		},
		{
			name:        "unknown_target_role",
			target:      "invalid_daemon",
			envOverride: "",
			want:        nil,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveAddresses(tt.target, tt.envOverride)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestCheckAddresses(t *testing.T) {
	ctx := context.Background()

	if err := CheckAddresses(ctx, nil, time.Second); err == nil {
		t.Fatal("expected error for empty address list, got nil")
	}

	origDial := dialAddr
	t.Cleanup(func() { dialAddr = origDial })

	dialAddr = defaultMockDial
	if err := CheckAddresses(ctx, []string{"127.0.0.1:29993"}, time.Second); err != nil {
		t.Fatalf("unexpected error on successful dial: %v", err)
	}

	dialAddr = failingMockDial
	if err := CheckAddresses(ctx, []string{"127.0.0.1:29994"}, time.Second); err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

func TestDefaultDial(t *testing.T) {
	origDialer := createDialer
	t.Cleanup(func() { createDialer = origDialer })

	createDialer = mockCreateDialer
	ctx := context.Background()

	activeMockDialer.err = errMockDial
	activeMockDialer.conn = nil
	if err := defaultDial(ctx, "127.0.0.1:29995", time.Second); err == nil {
		t.Fatal("expected error on failed dial, got nil")
	}

	activeMockDialer.err = nil
	activeMockDialer.conn = &mockFailingCloseConn{}
	if err := defaultDial(ctx, "127.0.0.1:29996", time.Second); err == nil {
		t.Fatal("expected error on failed close, got nil")
	}

	activeMockDialer.err = nil
	activeMockDialer.conn = &mockSuccessConn{}
	if err := defaultDial(ctx, "127.0.0.1:29997", time.Second); err != nil {
		t.Fatalf("unexpected error on successful dial: %v", err)
	}
}

func TestDefaultCreateDialer(t *testing.T) {
	dialer := defaultCreateDialer(time.Second)
	if dialer == nil {
		t.Fatal("expected non-nil dialer")
	}
}

func TestRun(t *testing.T) {
	origDial := dialAddr
	t.Cleanup(func() { dialAddr = origDial })

	ctx := context.Background()

	tests := []struct {
		mockDial func(context.Context, string, time.Duration) error
		name     string
		target   string
		wantCode int
	}{
		{
			name:     "unknown_target_failure",
			target:   "unknown",
			mockDial: defaultMockDial,
			wantCode: 1,
		},
		{
			name:     "healthy_dial_success",
			target:   targetHbbr,
			mockDial: defaultMockDial,
			wantCode: 0,
		},
		{
			name:     "unhealthy_dial_failure",
			target:   targetHbbr,
			mockDial: failingMockDial,
			wantCode: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialAddr = tt.mockDial
			if code := Run(ctx, []string{tt.target}, ""); code != tt.wantCode {
				t.Fatalf("expected exit code %d, got %d", tt.wantCode, code)
			}
		})
	}
}

func TestMain(t *testing.T) {
	origExit := exitFunc
	origDial := dialAddr
	origArgs := os.Args
	t.Cleanup(func() {
		exitFunc = origExit
		dialAddr = origDial
		os.Args = origArgs
	})

	exitFunc = mockExit
	dialAddr = defaultMockDial
	recordedExitCode = -1

	os.Args = []string{"probe", targetHbbr}
	main()

	if recordedExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", recordedExitCode)
	}
}
