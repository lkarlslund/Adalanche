package engine

import (
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

	graphA.addNew(
		Name, "Shared",
		DistinguishedName, "CN=Shared,OU=Users,DC=example,DC=com",
		DisplayName, "Shared A",
	)
	source := graphA.addNew(
		Name, "Source",
		DistinguishedName, "CN=Source,OU=Users,DC=example,DC=com",
	)
	_ = source

	sharedB := graphB.addNew(
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
	graph.addNew(
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
	loaderID.AddProcessor(func(tx *Tx) {
		beta, found := tx.Find(Name, NV("beta"))
		if !found {
			return
		}
		sawBeta = true
		tx.Node(beta).Set(DisplayName, NV("Beta display"))
	}, Processor{Description: "annotate beta", Phase: AfterMerge, Needs: []Product{"test/beta"}})

	loaderID.AddProcessor(func(tx *Tx) {
		tx.AddNew(Name, "beta", SAMAccountName, "BETA")
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
		t.Fatal("expected the annotating processor to see the added node")
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

func TestProcessorEdgesAppearAfterCommit(t *testing.T) {
	withProgressDisabled(t)
	withRegisteredProcessorsSnapshot(t)

	const loaderID LoaderID = 4343
	canControl := testEdge("delta-edge")
	var sawSource bool
	var sawTarget bool

	loaderID.AddProcessor(func(tx *Tx) {
		source, found := tx.Find(Name, NV("source"))
		if !found {
			return
		}
		sawSource = true
		target, found := tx.Find(Name, NV("target"))
		if !found {
			return
		}
		sawTarget = true
		tx.EdgeToEx(source, target, canControl, true)
	}, Processor{Description: "add edge", Phase: AfterMerge})

	graph := testGraph(
		testNamedNode("source"),
		testNamedNode("target"),
	)

	if err := RunPhase(graph, loaderID, AfterMerge); err != nil {
		t.Fatalf("process failed: %v", err)
	}
	if !sawSource || !sawTarget {
		t.Fatal("expected the processor to see both nodes")
	}

	source, _ := graph.Find(Name, NV("source"))
	target, _ := graph.Find(Name, NV("target"))
	edge, found := graph.GetEdge(source, target)
	if !found || !edge.IsSet(canControl) {
		t.Fatal("expected the edge to be committed")
	}
}

func TestProcessorOrderingErrors(t *testing.T) {
	withProgressDisabled(t)
	withRegisteredProcessorsSnapshot(t)

	const loaderID LoaderID = 4444
	noop := func(*Tx) {}
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

func TestProcessorOrderFollowsDependenciesUnderEverySeed(t *testing.T) {
	withProgressDisabled(t)

	const loaderID LoaderID = 4545
	run := func(seed uint64, reverse bool) []string {
		saved := slices.Clone(registeredProcessors)
		defer func() { registeredProcessors = saved }()
		SetProcessorSeed(seed)
		var order []string
		// Exclusive processors run one at a time, so the order they ran in
		// is the order the seed picked.
		record := func(name string) ExclusiveProcessorFunc {
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
			loaderID.AddExclusiveProcessor(record(spec.Description), spec)
		}
		if err := RunPhase(testGraph(), loaderID, AfterMerge); err != nil {
			t.Fatal(err)
		}
		return order
	}
	for seed := uint64(1); seed <= 20; seed++ {
		order := run(seed, false)
		at := func(name string) int { return slices.Index(order, name) }
		if at("consumer") < at("producer a") || at("consumer") < at("producer z") || at("final") != len(order)-1 {
			t.Fatalf("seed %d ran %v", seed, order)
		}
		if again := run(seed, true); !slices.Equal(order, again) {
			t.Fatalf("seed %d ran %v, and %v when registered in reverse", seed, order, again)
		}
	}
}
