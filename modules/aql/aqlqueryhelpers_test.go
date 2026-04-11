package aql

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
)

func TestPriorityQueueOrdering(t *testing.T) {
	n1 := engine.NewNode(engine.Name, "one")
	n2 := engine.NewNode(engine.Name, "two")
	n3 := engine.NewNode(engine.Name, "three")

	tests := []struct {
		name     string
		priority Priority
		states   []searchState
		want     []*engine.Node
	}{
		{
			name:     "shortest-first",
			priority: ShortestFirst,
			states: []searchState{
				{node: n3, currentTotalDepth: 5},
				{node: n2, currentTotalDepth: 2},
				{node: n1, currentTotalDepth: 1},
			},
			want: []*engine.Node{n1, n2, n3},
		},
		{
			name:     "probable-shortest",
			priority: ProbableShortest,
			states: []searchState{
				{node: n1, currentTotalDepth: 1, overAllProbabilityFraction: 0.5},
				{node: n2, currentTotalDepth: 3, overAllProbabilityFraction: 0.9},
				{node: n3, currentTotalDepth: 2, overAllProbabilityFraction: 0.7},
			},
			want: []*engine.Node{n2, n3, n1},
		},
		{
			name:     "longest-first",
			priority: LongestFirst,
			states: []searchState{
				{node: n1, currentTotalDepth: 1},
				{node: n2, currentTotalDepth: 4},
				{node: n3, currentTotalDepth: 2},
			},
			want: []*engine.Node{n2, n3, n1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queue := PriorityQueue{p: tt.priority}
			for _, state := range tt.states {
				queue.Push(state)
			}
			for i, want := range tt.want {
				if got := queue.Pop().node; got != want {
					t.Fatalf("pop %d: got %v want %v", i, got.Label(), want.Label())
				}
			}
		})
	}
}

func TestPriorityQueuePanicsOnInvalidOperations(t *testing.T) {
	var queue PriorityQueue
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic from empty pop")
		}
	}()
	queue.Pop()
}

func TestPriorityQueueDropBackPanicsOnInvalidCount(t *testing.T) {
	queue := PriorityQueue{items: []searchState{{}, {}}}
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic from invalid dropback")
		}
	}()
	queue.DropBack(3)
}

func TestProbableWorkingPathCloneAndReset(t *testing.T) {
	edgeType := engine.NewEdge("unit-test-aql-edge")
	edgeCombo := engine.NewIndexedGraph().EdgeBitmapToEdgeCombo(engine.EdgeBitmap{}.Set(edgeType))

	var path probableWorkingPath
	path.Add(1, engine.Out, edgeCombo, 0)
	path.Add(2, engine.Out, edgeCombo, 0)
	path.Add(3, engine.In, edgeCombo, 0)

	if !path.HasNode(2) {
		t.Fatal("expected path to contain node 2")
	}
	if !path.HasEdge(1, 2) {
		t.Fatal("expected path to contain 1->2 edge")
	}
	if !path.HasEdge(3, 2) {
		t.Fatal("expected path to track reverse edge direction")
	}

	cloned := path.Clone()
	cloned.path[0].target = 99
	if path.path[0].target == 99 {
		t.Fatal("expected clone to deep-copy path items")
	}

	path.Reset()
	if len(path.path) != 0 {
		t.Fatal("expected reset to clear path items")
	}
	if path.HasNode(1) {
		t.Fatal("expected reset to clear bloom filter")
	}
}

func TestProbableWorkingPathCommitToGraph(t *testing.T) {
	edgeAB := engine.NewEdge("unit-test-edge-ab")
	edgeBC := engine.NewEdge("unit-test-edge-bc")

	ao := engine.NewIndexedGraph()
	a := engine.NewNode(engine.Name, "A")
	b := engine.NewNode(engine.Name, "B")
	c := engine.NewNode(engine.Name, "C")
	ao.Add(a)
	ao.Add(b)
	ao.Add(c)

	comboAB := ao.EdgeBitmapToEdgeCombo(engine.EdgeBitmap{}.Set(edgeAB))
	comboBC := ao.EdgeBitmapToEdgeCombo(engine.EdgeBitmap{}.Set(edgeBC))

	var path probableWorkingPath
	path.Add(a.ID(), engine.Out, comboAB, 0)
	path.Add(b.ID(), engine.Out, comboAB, 255)
	path.Add(c.ID(), engine.In, comboBC, 255)

	result := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()
	path.CommitToGraph(ao, result, []NodeQuery{{Reference: "start"}})

	if reference := result.GetNodeData(a, "reference"); reference != "start" {
		t.Fatalf("expected node reference metadata, got %v", reference)
	}
	if !result.HasEdge(a, b) {
		t.Fatal("expected forward edge to be committed")
	}
	if !result.HasEdge(c, b) {
		t.Fatal("expected reverse edge direction to be committed")
	}
}

func BenchmarkPriorityQueuePushPop(b *testing.B) {
	queue := PriorityQueue{p: ShortestFirst}
	node := engine.NewNode(engine.Name, "bench")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		queue.Push(searchState{node: node, currentTotalDepth: byte(i % 8)})
		_ = queue.Pop()
	}
}

func BenchmarkProbableWorkingPathClone(b *testing.B) {
	var path probableWorkingPath
	for i := 0; i < 64; i++ {
		path.Add(engine.NodeID(i+1), engine.Out, 0, 255)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = path.Clone()
	}
}
