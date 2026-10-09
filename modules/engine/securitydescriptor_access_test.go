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
		{"deny Everyone", "D:(D;;CR;;;S-1-1-0)(A;;CR;;;S-1-5-21-1-2-3-1001)", 1, false},
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

func TestACLDeniesCountForTheTrusteeToken(t *testing.T) {
	acl, err := ParseSDDL("D:(D;;CR;;;S-1-5-21-1-2-3-1100)(A;;CR;;;S-1-5-21-1-2-3-1001)")
	if err != nil {
		t.Fatal(err)
	}
	group := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1100")
	inGroup := func(sid windowssecurity.SID) bool { return sid == group }
	if !acl.IsObjectClassAccessAllowedFor(1, nil, RIGHT_DS_CONTROL_ACCESS, uuid.Nil, nil, nil) {
		t.Fatal("a deny for another SID refused the grant without a token")
	}
	if acl.IsObjectClassAccessAllowedFor(1, nil, RIGHT_DS_CONTROL_ACCESS, uuid.Nil, nil, inGroup) {
		t.Fatal("a deny for a group in the trustee's token did not refuse the grant")
	}
}

func TestTrusteeAccessCheck(t *testing.T) {
	acl, err := ParseSDDL("D:(D;;WD;;;S-1-5-21-1-2-3-1100)(A;;RP;;;S-1-1-0)(A;;WDCR;;;S-1-5-21-1-2-3-1001)")
	if err != nil {
		t.Fatal(err)
	}
	sd := &SecurityDescriptor{Control: CONTROLFLAG_DACL_PRESENT, DACL: acl}
	trustee := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	group := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1100")
	inGroup := func(sid windowssecurity.SID) bool { return sid == group }
	for _, tt := range []struct {
		name  string
		mask  Mask
		token func(windowssecurity.SID) bool
		want  bool
	}{
		{"own grant", RIGHT_WRITE_DACL | RIGHT_DS_CONTROL_ACCESS, nil, true},
		{"grant to Everyone does not count", RIGHT_DS_READ_PROPERTY, nil, false},
		{"deny for a group in the token", RIGHT_WRITE_DACL, inGroup, false},
		{"deny for a group covers only some rights", RIGHT_DS_CONTROL_ACCESS, inGroup, true},
	} {
		if got := sd.TrusteeAccessCheck(trustee, tt.token, nil, tt.mask, uuid.Nil, NewIndexedGraph()); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestPropertySetACEsAcrossForests(t *testing.T) {
	attribute := uuid.Must(uuid.FromString("f3a64788-5306-11d1-a9c5-0000f80367c1"))
	propertySet := uuid.Must(uuid.FromString("bf9679c0-0de6-11d0-a285-00aa003049e2"))
	otherSet := uuid.Must(uuid.FromString("e48d0154-bcf8-11d1-8702-00c04fb96050"))
	trustee := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	acl := ACL{Entries: []ACE{{Type: ACETYPE_ACCESS_ALLOWED_OBJECT, Flags: OBJECT_TYPE_PRESENT, ObjectType: propertySet, Mask: RIGHT_DS_WRITE_PROPERTY, SID: trustee}}}

	schema := func(forest string, set uuid.UUID) *Node {
		return NewNode(DistinguishedName, "CN=Attribute,CN=Schema,CN=Configuration,"+forest, SchemaIDGUID, NV(attribute), AttributeSecurityGUID, NV(set))
	}
	inA := NewNode(DomainContext, "DC=child,DC=a,DC=test")
	inB := NewNode(DomainContext, "DC=b,DC=test")

	// Two forests that agree, as the merged graph holds them.
	agreeing := testGraph(schema("DC=a,DC=test", propertySet), schema("DC=b,DC=test", propertySet))
	for _, o := range []*Node{inA, inB} {
		if !acl.IsObjectClassAccessAllowed(0, o, RIGHT_DS_WRITE_PROPERTY, attribute, agreeing) {
			t.Fatalf("property set ACE not applied for %v when two forests' schemas agree", o.OneAttrString(DomainContext))
		}
	}

	// Forest b moved the attribute to another property set.
	differing := testGraph(schema("DC=a,DC=test", propertySet), schema("DC=b,DC=test", otherSet))
	if !acl.IsObjectClassAccessAllowed(0, inA, RIGHT_DS_WRITE_PROPERTY, attribute, differing) {
		t.Fatal("forest a's schema was not used for an object in forest a")
	}
	if acl.IsObjectClassAccessAllowed(0, inB, RIGHT_DS_WRITE_PROPERTY, attribute, differing) {
		t.Fatal("forest a's property set was applied to an object in forest b")
	}

	// A second domain tree of forest a, which only its crossRef places there.
	inTree := NewNode(DomainContext, "DC=tree,DC=test")
	treeRef := NewNode(DistinguishedName, "CN=TREE,CN=Partitions,CN=Configuration,DC=a,DC=test", ObjectClass, "crossRef", crossRefNCName, "DC=tree,DC=test")
	withTree := testGraph(schema("DC=a,DC=test", propertySet), schema("DC=b,DC=test", otherSet), treeRef)
	if !acl.IsObjectClassAccessAllowed(0, inTree, RIGHT_DS_WRITE_PROPERTY, attribute, withTree) {
		t.Fatal("forest a's schema was not used for an object in forest a's second tree")
	}
}
