package engine

import (
	"fmt"
	"slices"
	"strings"
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

func withRegisteredProcessorsSnapshot(t *testing.T) {
	t.Helper()

	snapshot := append([]processorInfo(nil), registeredProcessors...)
	t.Cleanup(func() {
		registeredProcessors = snapshot
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

func TestProcessorsRunAfterTheProductsTheyNeed(t *testing.T) {
	withProgressDisabled(t)
	withRegisteredProcessorsSnapshot(t)

	const loaderID LoaderID = 4242
	var sawBeta bool

	// Registered after its consumer, so only the dependency orders them.
	loaderID.AddNodePatchProcessor(func(view *FrozenGraph, out *NodePatchSet) {
		beta, found := view.Find(Name, NV("beta"))
		if !found {
			return
		}
		sawBeta = true
		out.Set(beta, DisplayName, NV("Beta display"))
	}, Processor{Description: "annotate beta", Phase: AfterMerge, Needs: []Product{"test/beta"}})

	loaderID.AddProcessor(func(ao *IndexedGraph) {
		ao.AddNew(Name, "beta", SAMAccountName, "BETA")
	}, Processor{Description: "add beta", Phase: AfterMerge, Provides: []Product{"test/beta"}})

	graph := testGraph(testNamedNode("alpha"))
	if err := RunPhase(graph, loaderID, AfterMerge); err != nil {
		t.Fatalf("process failed: %v", err)
	}

	beta, found := graph.Find(Name, NV("beta"))
	if !found {
		t.Fatal("expected beta node to be added")
	}
	if !sawBeta {
		t.Fatal("expected node patch processor to observe graph mutator output")
	}
	if got := beta.OneAttrString(DisplayName); got != "Beta display" {
		t.Fatalf("expected beta display name to be patched, got %q", got)
	}

	displayIndex := graph.GetIndex(DisplayName)
	nodes, found := displayIndex.Lookup(NV("beta display"))
	if !found || nodes.Len() != 1 || nodes.First() != beta {
		t.Fatal("expected patched display name to be reindexed")
	}
}

func TestProcessAppliesEdgeDeltaProcessorsAfterFrozenAnalysis(t *testing.T) {
	withProgressDisabled(t)
	withRegisteredProcessorsSnapshot(t)

	const loaderID LoaderID = 4343
	canControl := testEdge("delta-edge")
	var sawSource bool
	var sawTarget bool

	loaderID.AddEdgeDeltaProcessor(func(view *FrozenGraph, out *EdgeDelta) {
		source, found := view.Find(Name, NV("source"))
		if !found {
			return
		}
		sawSource = true
		target, found := view.Find(Name, NV("target"))
		if !found {
			return
		}
		sawTarget = true
		out.Add(source, target, canControl, true)
	}, Processor{Description: "add edge delta", Phase: AfterMerge})

	graph := testGraph(
		testNamedNode("source"),
		testNamedNode("target"),
	)

	if err := RunPhase(graph, loaderID, AfterMerge); err != nil {
		t.Fatalf("process failed: %v", err)
	}
	if !sawSource || !sawTarget {
		t.Fatal("expected edge delta processor to observe both nodes")
	}

	source, _ := graph.Find(Name, NV("source"))
	target, _ := graph.Find(Name, NV("target"))
	edge, found := graph.GetEdge(source, target)
	if !found || !edge.IsSet(canControl) {
		t.Fatal("expected edge delta to be applied")
	}
}

func TestProcessorOrderingErrors(t *testing.T) {
	withProgressDisabled(t)
	withRegisteredProcessorsSnapshot(t)

	const loaderID LoaderID = 4444
	noop := func(*IndexedGraph) {}
	loaderID.AddProcessor(noop, Processor{Description: "a", Phase: AfterMerge, Needs: []Product{"test/b"}, Provides: []Product{"test/a"}})
	loaderID.AddProcessor(noop, Processor{Description: "b", Phase: AfterMerge, Needs: []Product{"test/a"}, Provides: []Product{"test/b"}})
	if err := RunPhase(testGraph(), loaderID, AfterMerge); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected a cycle error, got %v", err)
	}

	registeredProcessors = registeredProcessors[:len(registeredProcessors)-2]
	loaderID.AddProcessor(noop, Processor{Description: "c", Phase: AfterMerge, Needs: []Product{"test/nobody"}})
	if err := RunPhase(testGraph(), loaderID, AfterMerge); err == nil || !strings.Contains(err.Error(), "no processor provides") {
		t.Fatalf("expected an unknown product error, got %v", err)
	}
}

func TestProcessorOrderDoesNotDependOnRegistration(t *testing.T) {
	withProgressDisabled(t)

	const loaderID LoaderID = 4545
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			withRegisteredProcessorsSnapshot(t)
			var order []string
			record := func(name string) ProcessorFunc {
				return func(*IndexedGraph) { order = append(order, name) }
			}
			specs := []Processor{
				{Description: "final", Phase: AfterMerge, Final: true},
				{Description: "consumer", Phase: AfterMerge, Needs: []Product{"test/x"}},
				{Description: "producer z", Phase: AfterMerge, Provides: []Product{"test/x"}},
				{Description: "producer a", Phase: AfterMerge, Provides: []Product{"test/x"}},
				{Description: "independent", Phase: AfterMerge},
			}
			if reverse {
				slices.Reverse(specs)
			}
			for _, spec := range specs {
				loaderID.AddProcessor(record(spec.Description), spec)
			}
			if err := RunPhase(testGraph(), loaderID, AfterMerge); err != nil {
				t.Fatal(err)
			}
			want := []string{"independent", "producer a", "producer z", "consumer", "final"}
			if !slices.Equal(order, want) {
				t.Fatalf("ran %v, want %v", order, want)
			}
		})
	}
}
