package engine

import "testing"

func TestNodeAbsorbMergesAndDeduplicatesAttributes(t *testing.T) {
	target := testNode(Name, "Alpha", Description, "Shared")
	source := testNode(Name, "Alpha", Description, "Shared", DisplayName, "Source")

	target.Absorb(source)

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
		node.Set(Name, nil)
	})
}

func TestNodeAdoptMovesChildAndRejectsDuplicate(t *testing.T) {
	parentA := testNamedNode("ParentA")
	parentB := testNamedNode("ParentB")
	child := testNamedNode("Child")

	parentA.Adopt(child)
	if child.Parent() != parentA {
		t.Fatal("expected child parent to be set")
	}
	if parentA.Children().Len() != 1 {
		t.Fatal("expected parent to track adopted child")
	}

	parentB.Adopt(child)
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
		parentB.Adopt(child)
	})
}

func TestNodeTypeCacheResetsOnTypeChange(t *testing.T) {
	node := testNamedNode("Alpha")
	node.Set(Type, NV(NodeTypeUser.Lookup()))
	if node.Type() != NodeTypeUser {
		t.Fatal("expected cached type lookup to resolve user type")
	}

	node.Set(Type, NV(NodeTypeOther.Lookup()))
	if node.Type() != NodeTypeOther {
		t.Fatal("expected type cache reset after Type attribute update")
	}
}
