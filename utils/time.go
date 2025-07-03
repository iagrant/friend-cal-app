package utils

import (
	"time"
)

// FormatTime converts a 24-hour time string (like "14:30")
// into a specified format ("12h" or "24h").
func FormatTime(timeStr string, formatPreference string) string {
	if timeStr == "" {
		return ""
	}

	// The layout for parsing a 24-hour time string.
	parseLayout := "15:04"
	t, err := time.Parse(parseLayout, timeStr)
	if err != nil {
		// If parsing fails, just return the original string.
		return timeStr
	}

	if formatPreference == "12h" {
		// The layout for formatting into a 12-hour time string.
		formatLayout := "3:04 PM"
		return t.Format(formatLayout)
	}

	// Default to returning the original 24-hour time.
	return timeStr
}
