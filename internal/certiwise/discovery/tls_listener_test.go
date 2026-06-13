package discovery

import (
	"crypto/tls"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

func TestTLSListenerPathIPv6(t *testing.T) {
	path := TLSListenerPath("::1", 443)
	if path != "tls://[::1]:443" {
		t.Fatalf("expected bracketed IPv6 path, got %q", path)
	}
}

func TestResolveListenTargetsExplicitPorts(t *testing.T) {
	targets := ResolveTLSListenerTargets(TLSListenerOptions{
		Enabled:             true,
		Hosts:               []string{"127.0.0.1"},
		StaticPorts:         []int{9443},
		StaticPortsExplicit: true,
	})

	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Port != 9443 {
		t.Fatalf("expected port 9443, got %d", targets[0].Port)
	}
}

func TestParsePortRangeCap(t *testing.T) {
	ports, truncated := parsePortRange("8000-8150")
	if !truncated {
		t.Fatal("expected truncated range")
	}
	if len(ports) != maxTLSListenerRangePorts {
		t.Fatalf("expected %d ports, got %d", maxTLSListenerRangePorts, len(ports))
	}
	if ports[0] != 8000 {
		t.Fatalf("expected start 8000, got %d", ports[0])
	}
}

func TestScanTLSListenersClosedPort(t *testing.T) {
	items := ScanTLSListeners(TLSListenerOptions{
		Enabled:             true,
		Hosts:               []string{"127.0.0.1"},
		StaticPorts:         []int{1},
		StaticPortsExplicit: true,
		Timeout:             500 * time.Millisecond,
		Insecure:            true,
	})
	if len(items) != 0 {
		t.Fatalf("expected no items for closed port, got %d", len(items))
	}
}

func TestScanTLSListenersFindsEphemeralServer(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	items := ScanTLSListeners(TLSListenerOptions{
		Enabled:             true,
		Hosts:               []string{"127.0.0.1"},
		StaticPorts:         []int{port},
		StaticPortsExplicit: true,
		Timeout:             3 * time.Second,
		Insecure:            true,
	})

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Source != tlsListenerSource {
		t.Fatalf("expected source %q, got %q", tlsListenerSource, items[0].Source)
	}
	if !strings.HasPrefix(items[0].Path, "tls://127.0.0.1:") {
		t.Fatalf("unexpected path %q", items[0].Path)
	}
	if len(items[0].Thumbprint) != 64 {
		t.Fatalf("expected 64-char thumbprint, got %q", items[0].Thumbprint)
	}
}

func TestScanTLSListenersSameCertDifferentPorts(t *testing.T) {
	base := httptest.NewTLSServer(nil)
	t.Cleanup(base.Close)
	cert := base.TLS.Certificates[0]

	serverA := httptest.NewUnstartedServer(nil)
	serverA.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	serverA.StartTLS()
	t.Cleanup(serverA.Close)

	serverB := httptest.NewUnstartedServer(nil)
	serverB.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	serverB.StartTLS()
	t.Cleanup(serverB.Close)

	portA, err := portFromURL(serverA.URL)
	if err != nil {
		t.Fatalf("port A: %v", err)
	}
	portB, err := portFromURL(serverB.URL)
	if err != nil {
		t.Fatalf("port B: %v", err)
	}

	items := ScanTLSListeners(TLSListenerOptions{
		Enabled:             true,
		Hosts:               []string{"127.0.0.1"},
		StaticPorts:         []int{portA, portB},
		StaticPortsExplicit: true,
		Timeout:             3 * time.Second,
		Insecure:            true,
	})

	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Thumbprint != items[1].Thumbprint {
		t.Fatalf("expected same thumbprint on both ports")
	}
	if items[0].Path == items[1].Path {
		t.Fatal("expected different paths for different ports")
	}
}

func TestPortsFromAssignmentsVerifyEndpoint(t *testing.T) {
	targets := portsFromAssignments([]certiwise.AssignmentPullItem{
		{
			Config: certiwise.AssignmentConfig{
				VerifyEndpoint: "https://api.example.com:8443/health",
			},
		},
	})

	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Host != "api.example.com" || targets[0].Port != 8443 {
		t.Fatalf("unexpected target %#v", targets[0])
	}
}

func TestScanMergeIncludesTLSListenerItems(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)

	port, err := portFromURL(server.URL)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	items := Scan(ScanOptions{
		MaxItems: 10,
		TLSListener: TLSListenerOptions{
			Enabled:             true,
			Hosts:               []string{"127.0.0.1"},
			StaticPorts:         []int{port},
			StaticPortsExplicit: true,
			Timeout:             3 * time.Second,
			Insecure:            true,
		},
	})

	found := false
	for _, item := range items {
	 if item.Source == tlsListenerSource {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected merged scan to include tls_listener item")
	}
}

func portFromURL(raw string) (int, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(parsed.Port())
}
