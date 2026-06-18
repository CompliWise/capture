package upgrade

import (
	"strings"
	"time"
)

var weekdayIndex = map[string]time.Weekday{
	"sun": time.Sunday,
	"mon": time.Monday,
	"tue": time.Tuesday,
	"wed": time.Wednesday,
	"thu": time.Thursday,
	"fri": time.Friday,
	"sat": time.Saturday,
}

// IsMaintenanceWindowOpen returns true when now falls inside windowUtc.
// Format: "Sun 02:00-06:00" (UTC). Empty window means always open.
func IsMaintenanceWindowOpen(windowUtc string, now time.Time) bool {
	windowUtc = strings.TrimSpace(windowUtc)
	if windowUtc == "" {
		return true
	}

	parts := strings.Fields(windowUtc)
	if len(parts) != 2 {
		return true
	}

	weekday, ok := weekdayIndex[strings.ToLower(parts[0])]
	if !ok {
		return true
	}

	rangeParts := strings.Split(parts[1], "-")
	if len(rangeParts) != 2 {
		return true
	}

	startMinutes, okStart := parseClockMinutes(rangeParts[0])
	endMinutes, okEnd := parseClockMinutes(rangeParts[1])
	if !okStart || !okEnd {
		return true
	}

	utcNow := now.UTC()
	if utcNow.Weekday() != weekday {
		return false
	}

	currentMinutes := utcNow.Hour()*60 + utcNow.Minute()
	if startMinutes <= endMinutes {
		return currentMinutes >= startMinutes && currentMinutes < endMinutes
	}
	return currentMinutes >= startMinutes || currentMinutes < endMinutes
}

func parseClockMinutes(value string) (int, bool) {
	segments := strings.Split(strings.TrimSpace(value), ":")
	if len(segments) != 2 {
		return 0, false
	}

	hour, errHour := parseInt(segments[0])
	minute, errMinute := parseInt(segments[1])
	if errHour != nil || errMinute != nil {
		return 0, false
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, false
	}

	return hour*60 + minute, true
}

func parseInt(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, &strconvError{value: value}
	}
	n := 0
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0, &strconvError{value: value}
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

type strconvError struct {
	value string
}

func (e *strconvError) Error() string {
	return "invalid integer: " + e.value
}
