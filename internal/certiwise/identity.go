package certiwise

import (
	"fmt"
	"os"
	"runtime"
)

// HostIdentity returns hostname and platform strings for enroll/heartbeat payloads.
func HostIdentity() (hostname string, platform string) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	return hostname, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
