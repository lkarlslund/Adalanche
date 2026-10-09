package collect

import (
	"regexp"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	is64Bit = uint64(^uintptr(0)) == ^uint64(0)
)

var (
	os64Bit              bool
	systemroot, _        = registry.ExpandString("%SystemRoot%")
	win32folder          = strings.ToLower(systemroot + `\system32`)
	win32native          = strings.ToLower(systemroot + `\sysnative`)
	programFilesVariable = regexp.MustCompile(`(?i)%ProgramFiles%`)
)

func init() {
	if is64Bit {
		os64Bit = true
		return
	}
	_ = windows.IsWow64Process(windows.CurrentProcess(), &os64Bit)
}

func resolvepath(input string) string {
	if !is64Bit && os64Bit {
		input = programFilesVariable.ReplaceAllString(input, "%ProgramW6432%")
	}
	output, _ := registry.ExpandString(input)
	if !is64Bit && os64Bit {
		if strings.EqualFold(output, win32folder) || strings.HasPrefix(strings.ToLower(output), win32folder+`\`) {
			// Inspect the native system directory, not the collector's redirected view.
			output = win32native + output[len(win32folder):]
		}
	}
	return output
}
