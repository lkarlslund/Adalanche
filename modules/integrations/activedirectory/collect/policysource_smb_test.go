package collect

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestOwnerAndDACL(t *testing.T) {
	// S-1-5-32-544 (BUILTIN\Administrators)
	owner := []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0}
	// ACL revision 2 with one ACCESS_ALLOWED ACE granting GENERIC_ALL to the owner SID
	ace := append([]byte{0, 0, byte(8 + len(owner)), 0, 0, 0, 0, 0x10}, owner...)
	acl := append([]byte{2, 0, byte(8 + len(ace)), 0, 1, 0, 0, 0}, ace...)

	sd := make([]byte, 20)
	sd[0] = 1
	binary.LittleEndian.PutUint16(sd[2:], 0x8004) // self-relative, DACL present
	binary.LittleEndian.PutUint32(sd[4:], 20)
	binary.LittleEndian.PutUint32(sd[16:], uint32(20+len(owner)))
	sd = append(append(sd, owner...), acl...)

	sid, dacl, err := ownerAndDACL(sd)
	if err != nil {
		t.Fatal(err)
	}
	if sid != windowssecurity.MustParseStringSID("S-1-5-32-544") {
		t.Fatalf("owner = %v", sid)
	}
	if !bytes.Equal(dacl, acl) {
		t.Fatalf("dacl = %x, want %x", dacl, acl)
	}

	binary.LittleEndian.PutUint32(sd[16:], 0)
	if _, dacl, err := ownerAndDACL(sd); err != nil || dacl != nil {
		t.Fatalf("no DACL: dacl=%x err=%v", dacl, err)
	}

	if _, _, err := ownerAndDACL(sd[:10]); err == nil {
		t.Fatal("expected error on truncated descriptor")
	}
}

func TestSplitUNC(t *testing.T) {
	share, rel, ok := splitUNC(`\\EXAMPLE.COM\sysvol\EXAMPLE.COM\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}`)
	if !ok || share != "sysvol" || rel != "EXAMPLE.COM/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}" {
		t.Fatalf("got %q %q %v", share, rel, ok)
	}
	if _, _, ok := splitUNC(`\\host`); ok {
		t.Fatal("expected failure without share")
	}
}
