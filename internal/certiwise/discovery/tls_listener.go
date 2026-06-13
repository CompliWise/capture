package discovery

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

const (
	tlsListenerSource         = "tls_listener"
	maxTLSListenerRangePorts  = 100
	defaultTLSListenerWorkers = 5
)

var defaultTLSListenerPorts = []int{443, 8443, 9443, 10443}

// TLSListenerPath returns the virtual inventory path for a TLS listener.
func TLSListenerPath(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("tls://[%s]:%d", host, port)
	}
	return fmt.Sprintf("tls://%s:%d", host, port)
}

// ResolveTLSListenerTargets builds deduped host:port scan targets.
func ResolveTLSListenerTargets(opts TLSListenerOptions) []TLSListenerTarget {
	hosts := opts.Hosts
	if len(hosts) == 0 {
		hosts = []string{"127.0.0.1", "::1"}
	}

	ports := make([]int, 0)
	if len(opts.StaticPorts) > 0 {
		ports = append(ports, opts.StaticPorts...)
	} else if !opts.StaticPortsExplicit {
		ports = append(ports, defaultTLSListenerPorts...)
	}

	if strings.TrimSpace(opts.PortRange) != "" {
		rangePorts, truncated := parsePortRange(opts.PortRange)
		if truncated {
			log.Printf("discovery: tls_listener range truncated to %d ports", maxTLSListenerRangePorts)
		}
		ports = append(ports, rangePorts...)
	}

	type targetKey struct {
		host string
		port int
	}
	seen := make(map[targetKey]struct{})
	targets := make([]TLSListenerTarget, 0)

	addTarget := func(host string, port int) {
		host = strings.TrimSpace(host)
		if host == "" || port < 1 || port > 65535 {
			return
		}
		key := targetKey{host: host, port: port}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		targets = append(targets, TLSListenerTarget{Host: host, Port: port})
	}

	for _, host := range hosts {
		for _, port := range ports {
			addTarget(host, port)
		}
	}

	for _, assignmentTarget := range portsFromAssignments(opts.Assignments) {
		addTarget(assignmentTarget.Host, assignmentTarget.Port)
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Host == targets[j].Host {
			return targets[i].Port < targets[j].Port
		}
		return targets[i].Host < targets[j].Host
	})

	return targets
}

func parsePortRange(raw string) ([]int, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false
	}

	parts := strings.Split(trimmed, "-")
	if len(parts) != 2 {
		return nil, false
	}

	start, errStart := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, errEnd := strconv.Atoi(strings.TrimSpace(parts[1]))
	if errStart != nil || errEnd != nil || start < 1 || end > 65535 || start > end {
		return nil, false
	}

	truncated := false
	count := end - start + 1
	if count > maxTLSListenerRangePorts {
		end = start + maxTLSListenerRangePorts - 1
		truncated = true
	}

	ports := make([]int, 0, end-start+1)
	for port := start; port <= end; port++ {
		ports = append(ports, port)
	}
	return ports, truncated
}

func portsFromAssignments(assignments []certiwise.AssignmentPullItem) []TLSListenerTarget {
	targets := make([]TLSListenerTarget, 0)
	for _, assignment := range assignments {
		endpoint := strings.TrimSpace(assignment.Config.VerifyEndpoint)
		if endpoint == "" {
			continue
		}

		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}

		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "https" && scheme != "tls" {
			continue
		}

		host := parsed.Hostname()
		if host == "" {
			continue
		}

		port := 443
		if portRaw := parsed.Port(); portRaw != "" {
			value, err := strconv.Atoi(portRaw)
			if err != nil || value < 1 || value > 65535 {
				continue
			}
			port = value
		}

		targets = append(targets, TLSListenerTarget{Host: host, Port: port})
	}
	return targets
}

// ScanTLSListeners probes configured host:port pairs and returns discovered items.
func ScanTLSListeners(opts TLSListenerOptions) []DiscoveredItem {
	if !opts.Enabled {
		return nil
	}

	targets := ResolveTLSListenerTargets(opts)
	if len(targets) == 0 {
		return nil
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	maxWorkers := opts.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = defaultTLSListenerWorkers
	}

	type result struct {
		item *DiscoveredItem
	}

	results := make(chan result, len(targets))
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Add(1)
		go func(target TLSListenerTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			item, err := probeTLSListener(target, timeout, opts.Insecure)
			if err != nil || item == nil {
				return
			}
			results <- result{item: item}
		}(target)
	}

	wg.Wait()
	close(results)

	items := make([]DiscoveredItem, 0, len(targets))
	for res := range results {
		if res.item != nil {
			items = append(items, *res.item)
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Path < items[j].Path
	})

	return items
}

func probeTLSListener(target TLSListenerTarget, timeout time.Duration, insecure bool) (*DiscoveredItem, error) {
	address := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}

	item := certToDiscoveredTLSListener(state.PeerCertificates[0], target)
	return &item, nil
}

func certToDiscoveredTLSListener(cert *x509.Certificate, target TLSListenerTarget) DiscoveredItem {
	path := TLSListenerPath(target.Host, target.Port)
	return certToItem(cert, tlsListenerSource, path, "", "")
}
