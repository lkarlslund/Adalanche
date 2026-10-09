package collect

import (
	"errors"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestLogonSessionMetadata(t *testing.T) {
	// Counted, non-NUL-terminated strings, including non-ASCII data.
	user := []uint16{'u', 0x00e6}
	domain := []uint16{'L', 'A', 'B'}
	packageName := []uint16{'N', 'T', 'L', 'M'}
	sid, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	data := logonDataPrefix{
		Size:           uint32(unsafe.Sizeof(logonDataPrefix{})),
		User:           windows.NTUnicodeString{Length: 4, MaximumLength: 4, Buffer: &user[0]},
		Domain:         windows.NTUnicodeString{Length: 6, MaximumLength: 6, Buffer: &domain[0]},
		Authentication: windows.NTUnicodeString{Length: 8, MaximumLength: 8, Buffer: &packageName[0]},
		Type:           10, Session: 7, SID: sid, Time: windows.NsecToFiletime(stamp.UnixNano()),
	}
	record := map[string]any{}
	if err := data.appendMetadata(record); err != nil {
		t.Fatal(err)
	}
	if record["User"] != "uæ" || record["Domain"] != "LAB" || record["AuthenticationPackage"] != "NTLM" || record["LogonType"] != uint32(10) || record["SessionID"] != uint32(7) || record["SID"] != "S-1-5-18" || record["LogonTime"] != stamp {
		t.Fatalf("metadata = %+v", record)
	}
	if len(record) != 7 {
		t.Fatalf("unexpected metadata fields: %+v", record)
	}
	// The copy must outlive the native allocation and its strings.
	user[0] = 'x'
	if record["User"] != "uæ" {
		t.Fatal("metadata retained native string backing memory")
	}
	data.Size += 128 // Newer APIs may return a larger structure.
	if err := data.appendMetadata(map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

func TestLogonSessionInvalidMetadata(t *testing.T) {
	size := uint32(unsafe.Sizeof(logonDataPrefix{}))
	for _, data := range []*logonDataPrefix{
		nil,
		{Size: size - 1},
		{Size: size, User: windows.NTUnicodeString{Length: 2, MaximumLength: 2}},
		{Size: size, Domain: windows.NTUnicodeString{Length: 3, MaximumLength: 4}},
		{Size: size, Authentication: windows.NTUnicodeString{Length: 4, MaximumLength: 2}},
	} {
		record := map[string]any{}
		if err := data.appendMetadata(record); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("invalid metadata returned %v", err)
		}
		if len(record) != 0 {
			t.Fatal("invalid metadata produced a partial identity")
		}
	}
	record := map[string]any{}
	if err := (&logonDataPrefix{Size: size}).appendMetadata(record); err != nil {
		t.Fatal(err)
	}
	if _, ok := record["SID"]; ok {
		t.Fatal("invented missing SID")
	}
	if _, ok := record["LogonTime"]; ok {
		t.Fatal("invented missing logon time")
	}
}
