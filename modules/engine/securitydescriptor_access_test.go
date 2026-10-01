package engine

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestACLAccessAllowedHonorsPrecedingDenies(t *testing.T) {
	for _, tt := range []struct {
		name  string
		sddl  string
		index int
		want  bool
	}{
		{"allow", "D:(A;;CR;;;S-1-5-21-1-2-3-1001)", 0, true},
		{"deny same trustee", "D:(D;;CR;;;S-1-5-21-1-2-3-1001)(A;;CR;;;S-1-5-21-1-2-3-1001)", 1, false},
		{"unrelated allow before inherited deny", "D:(A;;CR;;;S-1-5-21-1-2-3-1002)(D;ID;CR;;;S-1-5-21-1-2-3-1001)(A;ID;CR;;;S-1-5-21-1-2-3-1001)", 2, false},
		{"unrelated deny", "D:(D;;CR;;;S-1-5-21-1-2-3-1002)(A;;CR;;;S-1-5-21-1-2-3-1001)", 1, true},
		{"different right", "D:(D;;RP;;;S-1-5-21-1-2-3-1001)(A;;CR;;;S-1-5-21-1-2-3-1001)", 1, true},
		{"inherit only deny", "D:(D;IO;CR;;;S-1-5-21-1-2-3-1001)(A;;CR;;;S-1-5-21-1-2-3-1001)", 1, true},
		{"later deny", "D:(A;;CR;;;S-1-5-21-1-2-3-1001)(D;ID;CR;;;S-1-5-21-1-2-3-1001)", 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := ParseSDDL(tt.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if got := acl.IsObjectClassAccessAllowed(tt.index, nil, RIGHT_DS_CONTROL_ACCESS, uuid.Nil, nil); got != tt.want {
				t.Fatalf("access allowed = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACLUnsupportedACEIsNotAGrant(t *testing.T) {
	for _, kind := range []ACEType{0x02 /* audit */, ACETYPE_ACCESS_ALLOWED_CALLBACK} {
		acl := ACL{Entries: []ACE{{Type: kind, Mask: RIGHT_DS_CONTROL_ACCESS}}}
		if acl.IsObjectClassAccessAllowed(0, nil, RIGHT_DS_CONTROL_ACCESS, uuid.Nil, nil) {
			t.Errorf("ACE type %v incorrectly grants access", kind)
		}
	}
}

func TestACLPartialDenyBlocksMultiRightGrant(t *testing.T) {
	trustee := "S-1-5-21-1-2-3-1001"
	sid, _ := windowssecurity.ParseStringSID(trustee)
	for _, tt := range []struct {
		name      string
		denyMask  Mask
		denyFlags ACEFlags
		want      bool
	}{
		{"deny one of the requested rights", RIGHT_WRITE_DACL, 0, false},
		{"deny an unrequested right", RIGHT_SYNCRONIZE, 0, true},
		{"inherit-only partial deny", RIGHT_WRITE_DACL, ACEFLAG_INHERIT_ONLY_ACE, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			acl := ACL{containsdeny: true, Entries: []ACE{
				{Type: ACETYPE_ACCESS_DENIED, ACEFlags: tt.denyFlags, Mask: tt.denyMask, SID: sid},
				{Type: ACETYPE_ACCESS_ALLOWED, Mask: RIGHT_GENERIC_ALL, SID: sid},
			}}
			if got := acl.IsObjectClassAccessAllowed(1, nil, RIGHT_GENERIC_ALL, uuid.Nil, nil); got != tt.want {
				t.Fatalf("GenericAll allowed = %v, want %v", got, tt.want)
			}
			// A single right the deny does not cover is still granted.
			if !acl.IsObjectClassAccessAllowed(1, nil, RIGHT_WRITE_OWNER, uuid.Nil, nil) {
				t.Fatal("WRITE_OWNER should still be granted")
			}
		})
	}
}
