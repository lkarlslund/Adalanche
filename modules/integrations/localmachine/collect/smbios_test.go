package collect

import (
	"errors"
	"io/fs"
	"testing"
)

func rawSMBIOS(structures ...[]byte) []byte {
	var table []byte
	for _, s := range structures {
		table = append(table, s...)
	}
	n := len(table)
	return append([]byte{0, 3, 4, 0, byte(n), byte(n >> 8), 0, 0}, table...)
}

func systemInformation(uuid []byte) []byte {
	s := []byte{1, 0x1b, 0x01, 0x00, 1, 2, 0, 0}
	s = append(s, uuid...)
	s = append(s, 0x06, 0, 0, 0)        // wake-up type, SKU, family
	return append(s, 'A', 0, 'B', 0, 0) // strings
}

func TestSMBIOSSystemUUID(t *testing.T) {
	uuid := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	bios := append([]byte{0, 0x12, 0x00, 0x00}, make([]byte, 0x0e)...)
	bios = append(bios, 'v', 'e', 'n', 'd', 'o', 'r', 0, 0)
	end := []byte{127, 4, 0xff, 0xff, 0, 0}

	got, err := smbiosSystemUUID(rawSMBIOS(bios, systemInformation(uuid), end))
	if err != nil || got != "00112233-4455-6677-8899-AABBCCDDEEFF" {
		t.Fatalf("got %q, %v", got, err)
	}
	for name, raw := range map[string][]byte{
		"no system information": rawSMBIOS(bios, end),
		"zero uuid":             rawSMBIOS(systemInformation(make([]byte, 16)), end),
		"truncated":             rawSMBIOS(bios)[:20],
		"empty":                 nil,
	} {
		if _, err := smbiosSystemUUID(raw); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: got %v, want not found", name, err)
		}
	}
}
