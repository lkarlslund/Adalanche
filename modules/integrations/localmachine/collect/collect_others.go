//go:build !windows
// +build !windows

package collect

func platformSupported() bool { return false }
