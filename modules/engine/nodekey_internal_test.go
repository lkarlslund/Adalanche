package engine

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestRegisterPrimaryIDInsertsBeforeAndIsIdempotent(t *testing.T) {
	saved := append([]Attribute(nil), primaryidattrs...)
	defer func() { primaryidattrs = saved }()

	a := NewAttribute("zzTestKeyAttr").Type(AttributeTypeSID)
	RegisterPrimaryID(a, ObjectSid)
	ai, si := -1, -1
	for i, x := range primaryidattrs {
		if x == a {
			ai = i
		}
		if x == ObjectSid {
			si = i
		}
	}
	if ai < 0 || si < 0 || ai != si-1 {
		t.Fatalf("want the attr right before ObjectSid, got order %v", primaryidattrs)
	}
	RegisterPrimaryID(a, ObjectSid) // again
	count := 0
	for _, x := range primaryidattrs {
		if x == a {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("registered %d times, want 1", count)
	}
}

func TestParseNodeKeyParsesSIDTypedAttribute(t *testing.T) {
	NewAttribute("zzTestSidKey").Type(AttributeTypeSID)
	const text = "S-1-5-21-1-2-3-1105"
	attr, value, err := ParseNodeKey("zzTestSidKey=" + text)
	if err != nil {
		t.Fatal(err)
	}
	if attr.String() != "zzTestSidKey" || value.String() != text {
		t.Fatalf("parsed %v=%v", attr, value)
	}
	if _, ok := value.Raw().(windowssecurity.SID); !ok {
		t.Fatalf("value is not a SID: %T", value.Raw())
	}
}
