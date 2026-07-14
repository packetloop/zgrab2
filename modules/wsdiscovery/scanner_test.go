package wsdiscovery

import (
	"io"
	"net"
	"testing"
	"time"
)

// mockConn is a minimal net.Conn that returns a fixed response payload.
// Note: net.Pipe zero-byte writes block in Go 1.25, so we use this mock
// instead of net.Pipe for probes that send no data (e.g. requests[1] == "").
type mockConn struct {
	response []byte
}

func (m *mockConn) Read(b []byte) (int, error) {
	if len(m.response) == 0 {
		return 0, io.EOF
	}
	n := copy(b, m.response)
	m.response = m.response[n:]
	if len(m.response) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error)          { return len(b), nil }
func (m *mockConn) Close() error                         { return nil }
func (m *mockConn) LocalAddr() net.Addr                  { return nil }
func (m *mockConn) RemoteAddr() net.Addr                 { return nil }
func (m *mockConn) SetDeadline(t time.Time) error        { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error    { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error   { return nil }

func TestMinVulnerableSize(t *testing.T) {
	if min_vulnerable_size != 200 {
		t.Errorf("min_vulnerable_size: got %d, want 200", min_vulnerable_size)
	}
}

func TestRequests(t *testing.T) {
	if len(requests) != 4 {
		t.Fatalf("requests length: got %d, want 4", len(requests))
	}
	if requests[0] != "3c2e3e00" {
		t.Errorf("requests[0]: got %q, want %q", requests[0], "3c2e3e00")
	}
}

func TestIsTargetVulnerable_LargeResponse(t *testing.T) {
	conn := &mockConn{response: make([]byte, min_vulnerable_size+1)}
	vuln, _, err := IsTargetVulnerable("3c2e3e00", conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vuln {
		t.Error("expected vulnerable=true for response larger than threshold")
	}
}

func TestIsTargetVulnerable_SmallResponse(t *testing.T) {
	conn := &mockConn{response: make([]byte, min_vulnerable_size-1)}
	vuln, _, err := IsTargetVulnerable("3c2e3e00", conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vuln {
		t.Error("expected vulnerable=false for response smaller than threshold")
	}
}

func TestIsTargetVulnerable_ExactThresholdResponse(t *testing.T) {
	conn := &mockConn{response: make([]byte, min_vulnerable_size)}
	vuln, _, err := IsTargetVulnerable("3c2e3e00", conn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vuln {
		t.Error("expected vulnerable=false at exact threshold (condition is >, not >=)")
	}
}
