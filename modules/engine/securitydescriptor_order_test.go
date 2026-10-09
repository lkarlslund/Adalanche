package engine

import (
	"encoding/binary"
	"testing"

	"github.com/gofrs/uuid/v5"
)

// rawACE encodes a plain ACE for a SID given in binary form.
func rawACE(aceType ACEType, flags ACEFlags, mask Mask, sid []byte) []byte {
	ace := make([]byte, 8, 8+len(sid))
	ace[0], ace[1] = byte(aceType), byte(flags)
	binary.LittleEndian.PutUint16(ace[2:], uint16(8+len(sid)))
	binary.LittleEndian.PutUint32(ace[4:], uint32(mask))
	return append(ace, sid...)
}

// rawDescriptor encodes a self-relative security descriptor with only a DACL.
func rawDescriptor(aces ...[]byte) []byte {
	sd := make([]byte, 20)
	sd[0] = 1
	binary.LittleEndian.PutUint16(sd[2:], uint16(CONTROLFLAG_DACL_PRESENT))
	binary.LittleEndian.PutUint32(sd[16:], 20)
	acl := make([]byte, 8)
	acl[0] = 2
	for _, ace := range aces {
		acl = append(acl, ace...)
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	return append(sd, acl...)
}

var (
	everyoneBytes = []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	userBytes     = []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xe9, 3, 0, 0}
)

// An allow inherited from the parent comes before a deny inherited from the
// grandparent. That is canonical, and Windows evaluates it as stored, so the
// allow wins; moving the deny first would refuse it.
func TestDACLKeepsStoredOrder(t *testing.T) {
	sd, err := ParseSecurityDescriptor(rawDescriptor(
		rawACE(ACETYPE_ACCESS_ALLOWED, ACEFLAG_INHERITED_ACE, RIGHT_WRITE_DACL, userBytes),
		rawACE(ACETYPE_ACCESS_DENIED, ACEFLAG_INHERITED_ACE, RIGHT_WRITE_DACL, everyoneBytes),
	))
	if err != nil {
		t.Fatal(err)
	}
	if sd.DACL.Entries[0].Type != ACETYPE_ACCESS_ALLOWED || sd.DACL.Entries[1].Type != ACETYPE_ACCESS_DENIED {
		t.Fatalf("entries reordered: %v, %v", sd.DACL.Entries[0].Type, sd.DACL.Entries[1].Type)
	}
	if sd.DACL.HadSortingProblem {
		t.Error("inherited ACEs from two generations reported as not canonical")
	}
	if !sd.DACL.IsObjectClassAccessAllowed(0, NewNode(), RIGHT_WRITE_DACL, uuid.Nil, nil) {
		t.Error("the allow before the deny was refused")
	}
}

func TestIsCanonical(t *testing.T) {
	allow := ACE{Type: ACETYPE_ACCESS_ALLOWED}
	deny := ACE{Type: ACETYPE_ACCESS_DENIED_OBJECT}
	inheritedAllow := ACE{Type: ACETYPE_ACCESS_ALLOWED_OBJECT, ACEFlags: ACEFLAG_INHERITED_ACE}
	inheritedDeny := ACE{Type: ACETYPE_ACCESS_DENIED, ACEFlags: ACEFLAG_INHERITED_ACE}
	for _, tt := range []struct {
		name    string
		entries []ACE
		want    bool
	}{
		{"empty", nil, true},
		{"explicit deny, allow, inherited", []ACE{deny, allow, inheritedDeny, inheritedAllow}, true},
		{"inherited generations", []ACE{allow, inheritedDeny, inheritedAllow, inheritedDeny, inheritedAllow}, true},
		{"explicit allow before deny", []ACE{allow, deny}, false},
		{"explicit after inherited", []ACE{inheritedAllow, allow}, false},
	} {
		if got := (ACL{Entries: tt.entries}).IsCanonical(); got != tt.want {
			t.Errorf("%s: got %v", tt.name, got)
		}
	}
}
