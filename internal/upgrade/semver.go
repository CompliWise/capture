package upgrade

import (
	"strconv"
	"strings"
)

// CompareVersions compares semantic versions, ignoring build metadata after '+'.
// Returns -1 when current < target, 0 when equal, 1 when current > target.
func CompareVersions(current, target string) int {
	currentCore := coreVersion(current)
	targetCore := coreVersion(target)

	currentParts := parseVersionParts(currentCore)
	targetParts := parseVersionParts(targetCore)

	for i := 0; i < 3; i++ {
		switch {
		case currentParts[i] < targetParts[i]:
			return -1
		case currentParts[i] > targetParts[i]:
			return 1
		}
	}

	return 0
}

func coreVersion(version string) string {
	version = strings.TrimSpace(version)
	if idx := strings.Index(version, "+"); idx >= 0 {
		version = version[:idx]
	}
	if idx := strings.Index(version, "-"); idx >= 0 {
		version = version[:idx]
	}
	return version
}

func parseVersionParts(version string) [3]int {
	parts := [3]int{}
	segments := strings.Split(version, ".")
	for i := 0; i < len(segments) && i < 3; i++ {
		value, err := strconv.Atoi(segments[i])
		if err != nil {
			continue
		}
		parts[i] = value
	}
	return parts
}
