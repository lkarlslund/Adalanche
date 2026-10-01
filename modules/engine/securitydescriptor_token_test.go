package engine

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestAccessCheckFollowsTheAccessCheckAlgorithm(t *testing.T) {
	member, _ := windowssecurity.ParseStringSID("S-1-5-21-1-2-3-1001")
	group, _ := windowssecurity.ParseStringSID("S-1-5-21-1-2-3-2001")
	outsider, _ := windowssecurity.ParseStringSID("S-1-5-21-1-2-3-3001")
	right, _ := uuid.FromString("edacfd8f-ffb3-11d1-b41d-00a0c968f939")
	other, _ := uuid.FromString("00299570-246d-11d0-a768-00aa006e0529")
	token := func(sid windowssecurity.SID) bool { return sid == member || sid == group }

	allow := func(sid windowssecurity.SID, mask Mask) ACE {
		return ACE{Type: ACETYPE_ACCESS_ALLOWED, Mask: mask, SID: sid}
	}
	deny := func(sid windowssecurity.SID, mask Mask) ACE {
		return ACE{Type: ACETYPE_ACCESS_DENIED, Mask: mask, SID: sid}
	}
	object := func(t ACEType, sid windowssecurity.SID, mask Mask, g uuid.UUID) ACE {
		return ACE{Type: t, Flags: OBJECT_TYPE_PRESENT, ObjectType: g, Mask: mask, SID: sid}
	}

	for _, tt := range []struct {
		name string
		aces []ACE
		mask Mask
		guid uuid.UUID
		want bool
	}{
		{"allow through a group", []ACE{allow(group, RIGHT_WRITE_DACL)}, RIGHT_WRITE_DACL, uuid.Nil, true},
		{"allow for someone else", []ACE{allow(outsider, RIGHT_WRITE_DACL)}, RIGHT_WRITE_DACL, uuid.Nil, false},
		{"rights add up across ACEs", []ACE{allow(member, RIGHT_WRITE_DACL), allow(group, RIGHT_WRITE_OWNER)}, RIGHT_WRITE_DACL | RIGHT_WRITE_OWNER, uuid.Nil, true},
		{"partial deny before allow", []ACE{deny(group, RIGHT_WRITE_DACL), allow(member, RIGHT_GENERIC_ALL)}, RIGHT_GENERIC_ALL, uuid.Nil, false},
		{"deny after a full allow", []ACE{allow(member, RIGHT_GENERIC_ALL), deny(group, RIGHT_WRITE_DACL)}, RIGHT_GENERIC_ALL, uuid.Nil, true},
		{"deny of an unrequested right", []ACE{deny(group, RIGHT_WRITE_OWNER), allow(member, RIGHT_WRITE_DACL)}, RIGHT_WRITE_DACL, uuid.Nil, true},
		{"deny for an outsider", []ACE{deny(outsider, RIGHT_WRITE_DACL), allow(member, RIGHT_WRITE_DACL)}, RIGHT_WRITE_DACL, uuid.Nil, true},
		{"object allow for the right", []ACE{object(ACETYPE_ACCESS_ALLOWED_OBJECT, group, RIGHT_DS_CONTROL_ACCESS, right)}, RIGHT_DS_CONTROL_ACCESS, right, true},
		{"object allow for another right", []ACE{object(ACETYPE_ACCESS_ALLOWED_OBJECT, group, RIGHT_DS_CONTROL_ACCESS, other)}, RIGHT_DS_CONTROL_ACCESS, right, false},
		{"object deny for the right", []ACE{object(ACETYPE_ACCESS_DENIED_OBJECT, group, RIGHT_DS_CONTROL_ACCESS, right), allow(member, RIGHT_DS_CONTROL_ACCESS)}, RIGHT_DS_CONTROL_ACCESS, right, false},
		{"object deny for another right", []ACE{object(ACETYPE_ACCESS_DENIED_OBJECT, group, RIGHT_DS_CONTROL_ACCESS, other), allow(member, RIGHT_DS_CONTROL_ACCESS)}, RIGHT_DS_CONTROL_ACCESS, right, true},
		{"inherit-only ACEs are skipped", []ACE{{Type: ACETYPE_ACCESS_ALLOWED, ACEFlags: ACEFLAG_INHERIT_ONLY_ACE, Mask: RIGHT_WRITE_DACL, SID: member}}, RIGHT_WRITE_DACL, uuid.Nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sd := SecurityDescriptor{Control: CONTROLFLAG_DACL_PRESENT, DACL: ACL{Entries: tt.aces}}
			if got := sd.AccessCheck(token, nil, tt.mask, tt.guid, NewIndexedGraph()); got != tt.want {
				t.Fatalf("AccessCheck = %v, want %v", got, tt.want)
			}
		})
	}

	if !(&SecurityDescriptor{}).AccessCheck(token, nil, RIGHT_WRITE_DACL, uuid.Nil, nil) {
		t.Fatal("a missing DACL grants everything")
	}
}

func TestInheritedObjectTypeDoesNotLimitEffectiveACE(t *testing.T) {
	trustee, _ := windowssecurity.ParseStringSID("S-1-5-21-1-2-3-1001")
	userClass, _ := uuid.FromString("bf967aba-0de6-11d0-a285-00aa003049e2")
	acl := ACL{Entries: []ACE{{
		Type: ACETYPE_ACCESS_ALLOWED_OBJECT, Flags: INHERITED_OBJECT_TYPE_PRESENT,
		InheritedObjectType: userClass, Mask: RIGHT_WRITE_DACL, SID: trustee,
	}}}
	group := NewNode(Name, "a group, not a user")
	if !acl.IsObjectClassAccessAllowed(0, group, RIGHT_WRITE_DACL, uuid.Nil, NewIndexedGraph()) {
		t.Fatal("an effective ACE applies regardless of its inherited object type")
	}
}
