package engine

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestNodeAbsorbMergesAndDeduplicatesAttributes(t *testing.T) {
	target := testNode(Name, "Alpha", Description, "Shared")
	source := testNode(Name, "Alpha", Description, "Shared", DisplayName, "Source")

	target.absorb(source)

	if got := target.Attr(Description); got.Len() != 1 || got.First().String() != "Shared" {
		t.Fatalf("expected deduplicated description, got %v", got.StringSlice())
	}
	if got := target.OneAttrString(DisplayName); got != "Source" {
		t.Fatalf("expected absorbed display name, got %q", got)
	}
}

func TestNodeSetRejectsNilValue(t *testing.T) {
	node := testNamedNode("Alpha")
	requirePanic(t, func() {
		node.set(Name, AttributeValue{})
	})
}

func TestNodeAdoptMovesChildAndRejectsDuplicate(t *testing.T) {
	parentA := testNamedNode("ParentA")
	parentB := testNamedNode("ParentB")
	child := testNamedNode("Child")

	parentA.adopt(child)
	if child.Parent() != parentA {
		t.Fatal("expected child parent to be set")
	}
	if parentA.Children().Len() != 1 {
		t.Fatal("expected parent to track adopted child")
	}

	parentB.adopt(child)
	if child.Parent() != parentB {
		t.Fatal("expected child parent to move on re-adoption")
	}
	if parentA.Children().Len() != 0 {
		t.Fatal("expected previous parent child list to be updated")
	}
	if parentB.Children().Len() != 1 {
		t.Fatal("expected new parent child list to contain child")
	}

	requirePanic(t, func() {
		parentB.adopt(child)
	})
}

func TestNodeTypeCacheResetsOnTypeChange(t *testing.T) {
	node := testNamedNode("Alpha")
	node.set(Type, NV(NodeTypeUser.Lookup()))
	if node.Type() != NodeTypeUser {
		t.Fatal("expected cached type lookup to resolve user type")
	}

	node.set(Type, NV(NodeTypeOther.Lookup()))
	if node.Type() != NodeTypeOther {
		t.Fatal("expected type cache reset after Type attribute update")
	}
}

// SID() reflects objectSid after it changes, even when it was read before.
func TestNodeSIDFollowsObjectSidWrites(t *testing.T) {
	first := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3")
	second := windowssecurity.MustParseStringSID("S-1-5-21-4-5-6")
	n := NewNode(Name, "machine")
	if !n.SID().IsBlank() {
		t.Fatal("SID without objectSid")
	}
	n.set(ObjectSid, NVSID(first))
	if n.SID() != first {
		t.Fatal("SID cached from before objectSid was set")
	}
	n.set(ObjectSid, NVSID(second))
	if n.SID() != second {
		t.Fatal("SID cached from before objectSid changed")
	}
	n.clear(ObjectSid)
	if !n.SID().IsBlank() {
		t.Fatal("SID cached after objectSid was cleared")
	}
}
