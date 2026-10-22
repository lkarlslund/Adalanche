//go:build !linux

package aql

// systemMemory is only known on Linux; elsewhere the memory limit alone guards.
func systemMemory() (available, total uint64, ok bool) { return 0, 0, false }
