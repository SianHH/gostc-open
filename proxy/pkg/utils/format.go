package utils

import "fmt"

const (
	KB = 1 << 10
	MB = 1 << 20
	GB = 1 << 30
)

func FormatBytes[T int | int64 | uint64](bytes T) string {
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2fGB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2fMB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2fKB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
