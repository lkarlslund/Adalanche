package collect

import (
	"encoding/binary"
	"fmt"
	"io/fs"
)

// smbiosSystemUUID returns the UUID of the SMBIOS System Information
// structure (type 1) in raw firmware table data as returned for the 'RSMB'
// provider, formatted as Windows reports it. A table without one, or with a
// UUID the firmware marks as absent (all zeros or all ones), gives
// fs.ErrNotExist.
func smbiosSystemUUID(raw []byte) (string, error) {
	// RawSMBIOSData: calling method, major, minor, DMI revision, then the
	// table length and the table.
	if len(raw) < 8 {
		return "", fmt.Errorf("short SMBIOS data: %w", fs.ErrNotExist)
	}
	length := int(binary.LittleEndian.Uint32(raw[4:8]))
	table := raw[8:]
	if length < len(table) {
		table = table[:length]
	}
	for offset := 0; offset+4 <= len(table); {
		kind, formatted := table[offset], int(table[offset+1])
		if formatted < 4 || offset+formatted > len(table) {
			break
		}
		if kind == 1 && formatted >= 0x18 {
			return formatSMBIOSUUID(table[offset+8 : offset+24])
		}
		if kind == 127 { // end of table
			break
		}
		// The formatted area is followed by strings, ended by two zero bytes.
		next := offset + formatted
		for next+1 < len(table) && (table[next] != 0 || table[next+1] != 0) {
			next++
		}
		offset = next + 2
	}
	return "", fs.ErrNotExist
}

func formatSMBIOSUUID(u []byte) (string, error) {
	zeros, ones := true, true
	for _, b := range u {
		zeros = zeros && b == 0
		ones = ones && b == 0xff
	}
	if zeros || ones {
		return "", fs.ErrNotExist
	}
	// The first three fields are little-endian (SMBIOS 2.6 and later, and
	// how Windows reads them).
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X",
		binary.LittleEndian.Uint32(u[0:4]), binary.LittleEndian.Uint16(u[4:6]), binary.LittleEndian.Uint16(u[6:8]),
		u[8:10], u[10:16]), nil
}
