package aql

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// systemMemory reads the memory the system can still give out, and its total.
func systemMemory() (available, total uint64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	var found int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() && found < 2 {
		name, rest, _ := strings.Cut(scanner.Text(), ":")
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		kib, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch name {
		case "MemAvailable":
			available, found = kib<<10, found+1
		case "MemTotal":
			total, found = kib<<10, found+1
		}
	}
	return available, total, found == 2
}
