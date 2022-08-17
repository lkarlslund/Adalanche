package collect

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/shirou/gopsutil/v3/host"
	"golang.org/x/sys/windows/registry"
)

const (
	is64Bit = uint64(^uintptr(0)) == ^uint64(0)
)

var (
	os64Bit       bool
	systemroot, _ = registry.ExpandString("%SystemRoot%")
	win32folder   = strings.ToLower(systemroot + `\system32`)
	win32native   = strings.ToLower(systemroot + `\sysnative`)
)

func init() {
	h, _ := host.Info()
	os64Bit = h.KernelArch == "x86_64"
}

func resolvepath(input string) string {
	if !is64Bit && os64Bit {
		input = strings.ReplaceAll(input, "%ProgramFiles%", "%ProgramW6432%")
	}
	output, _ := registry.ExpandString(input)
	if !is64Bit && os64Bit {
		if strings.HasPrefix(strings.ToLower(output), win32folder) {
			// We're compiled as 32 bit, running on 64-bit and the path points into the SYSTEM32 folder - umbork it
			ui.Debug().Msgf("Unborking %v", output)
			output = win32native + output[len(win32folder):]
			ui.Debug().Msgf("Unborked to %v", output)
		}
	}
	return output
}
