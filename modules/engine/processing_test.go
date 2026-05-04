package engine

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/ui"
)

type testLoader struct {
	name string
}

func (l testLoader) Name() string { return l.name }
func (l testLoader) Init() error  { return nil }
func (l testLoader) Load(string, ProgressCallbackFunc) error {
	return ErrUninterested
}
func (l testLoader) Close() ([]*IndexedGraph, error) { return nil, nil }

func withProgressDisabled(t *testing.T) {
	t.Helper()

	previous := ui.ProgressEnabled()
	ui.SetProgressEnabled(false)
	t.Cleanup(func() {
		ui.SetProgressEnabled(previous)
	})
}

func TestMergeGraphsMergesDuplicateDistinguishedNames(t *testing.T) {
	withProgressDisabled(t)

	graphA := NewLoaderObjects(testLoader{name: "loader-a"})
	graphB := NewLoaderObjects(testLoader{name: "loader-b"})

	graphA.AddNew(
		Name, "Shared",
		DistinguishedName, "CN=Shared,OU=Users,DC=example,DC=com",
		DisplayName, "Shared A",
	)
	source := graphA.AddNew(
		Name, "Source",
		DistinguishedName, "CN=Source,OU=Users,DC=example,DC=com",
	)
	_ = source

	sharedB := graphB.AddNew(
		Name, "Shared",
		DistinguishedName, "CN=Shared,OU=Users,DC=example,DC=com",
		Description, "Shared B",
	)
	_ = sharedB

	merged, err := MergeGraphs([]*IndexedGraph{graphA, graphB})
	if err != nil {
		t.Fatalf("merge graphs failed: %v", err)
	}

	shared, found := merged.Find(DistinguishedName, NV("CN=Shared,OU=Users,DC=example,DC=com"))
	if !found {
		t.Fatal("expected merged shared node")
	}
	if got := shared.OneAttrString(DisplayName); got != "Shared A" {
		t.Fatalf("expected display name from first shared node, got %q", got)
	}
	if got := shared.OneAttrString(Description); got != "Shared B" {
		t.Fatalf("expected merged description from second shared node, got %q", got)
	}
}

func TestMergeGraphsAssignsOrphansToOrphanContainer(t *testing.T) {
	withProgressDisabled(t)

	graph := NewLoaderObjects(testLoader{name: "loader-a"})
	graph.AddNew(
		Name, "Orphan",
		DistinguishedName, "CN=Orphan,DC=example,DC=com",
	)

	merged, err := MergeGraphs([]*IndexedGraph{graph})
	if err != nil {
		t.Fatalf("merge graphs failed: %v", err)
	}

	mergedOrphan, found := merged.Find(DistinguishedName, NV("CN=Orphan,DC=example,DC=com"))
	if !found {
		t.Fatal("expected orphan node in merged graph")
	}
	parent := mergedOrphan.Parent()
	if parent == nil || parent.OneAttrString(Name) != "Orphans" {
		t.Fatalf("expected orphan container parent, got %#v", parent)
	}

	root := merged.Root()
	if root == nil || root.OneAttrString(Name) != "Adalanche root node" {
		t.Fatalf("expected synthetic merge root, got %#v", root)
	}
	if parent.Parent() != root {
		t.Fatal("expected orphan container under merged root")
	}
}
