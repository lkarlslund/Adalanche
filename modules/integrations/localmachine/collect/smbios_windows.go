package collect

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getSystemFirmwareTable = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")

// readSMBIOS returns the raw SMBIOS firmware table.
func readSMBIOS() ([]byte, error) {
	if err := getSystemFirmwareTable.Find(); err != nil {
		return nil, errors.ErrUnsupported
	}
	const rsmb = 0x52534D42 // 'RSMB'
	size, _, err := getSystemFirmwareTable.Call(rsmb, 0, 0, 0)
	if size == 0 {
		return nil, err
	}
	buffer := make([]byte, size)
	written, _, err := getSystemFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buffer[0])), size)
	if written == 0 || written > size {
		return nil, err
	}
	return buffer[:written], nil
}

// collectSMBIOSUUID returns the firmware's system UUID.
func collectSMBIOSUUID() (string, error) {
	raw, err := readSMBIOS()
	if err != nil {
		return "", err
	}
	return smbiosSystemUUID(raw)
}
