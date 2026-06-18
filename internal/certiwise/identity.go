package certiwise

import (
	"fmt"
	"os"
	"runtime"

	"github.com/compliwise/capture/internal/metric"
	"github.com/shirou/gopsutil/v4/host"
)

// HostMetadata describes identity and OS details for enroll/heartbeat payloads.
type HostMetadata struct {
	Hostname      string
	Platform      string
	OsPrettyName  string
	OsFamily      string
	OsPlatform    string
	OsVersion     string
	KernelVersion string
}

// CollectHostMetadata gathers hostname, runtime platform, and OS details.
func CollectHostMetadata() HostMetadata {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}

	platform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	hostInfo, hostErrors := metric.GetHostInformation()
	if hostInfo == nil || len(hostErrors) > 0 {
		return HostMetadata{
			Hostname: hostname,
			Platform: platform,
		}
	}

	metadata := HostMetadata{
		Hostname:      hostname,
		Platform:      platform,
		OsPrettyName:  hostInfo.PrettyName,
		OsFamily:      hostInfo.Os,
		OsPlatform:    hostInfo.Platform,
		KernelVersion: hostInfo.KernelVersion,
	}

	if info, err := host.Info(); err == nil && info.PlatformVersion != "" {
		metadata.OsVersion = info.PlatformVersion
	}

	return metadata
}

// HostIdentity returns hostname and platform strings for enroll/heartbeat payloads.
func HostIdentity() (hostname string, platform string) {
	metadata := CollectHostMetadata()
	return metadata.Hostname, metadata.Platform
}
