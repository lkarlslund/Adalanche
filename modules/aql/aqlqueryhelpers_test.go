package aql

import (
	"sort"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/graph"
)

func TestPriorityQueueOrdering(t *testing.T) {
	const n1, n2, n3 uint32 = 1, 2, 3

	tests := []struct {
		name     string
		priority Priority
		states   []searchState
		want     []uint32
	}{
		{
			name:     "shortest-first",
			priority: ShortestFirst,
			states: []searchState{
				{rank: n3, currentTotalDepth: 5},
				{rank: n2, currentTotalDepth: 2},
				{rank: n1, currentTotalDepth: 1},
			},
			want: []uint32{n1, n2, n3},
		},
		{
			name:     "probable-shortest",
			priority: ProbableShortest,
			states: []searchState{
				{rank: n1, currentTotalDepth: 1, overAllProbabilityFraction: 0.5},
				{rank: n2, currentTotalDepth: 3, overAllProbabilityFraction: 0.9},
				{rank: n3, currentTotalDepth: 2, overAllProbabilityFraction: 0.7},
			},
			want: []uint32{n2, n3, n1},
		},
		{
			name:     "longest-first",
			priority: LongestFirst,
			states: []searchState{
				{rank: n1, currentTotalDepth: 1},
				{rank: n2, currentTotalDepth: 4},
				{rank: n3, currentTotalDepth: 2},
			},
			want: []uint32{n2, n3, n1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queue := PriorityQueue{p: tt.priority}
			for _, state := range tt.states {
				queue.Push(state)
			}
			for i, want := range tt.want {
				if got := queue.Pop().rank; got != want {
					t.Fatalf("pop %d: got %v want %v", i, got, want)
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

func TestPathArena(t *testing.T) {
	edgeType := engine.NewEdge("unit-test-aql-edge")
	edgeCombo := engine.NewIndexedGraph().EdgeBitmapToEdgeCombo(engine.EdgeBitmap{}.Set(edgeType))

	var paths pathArena
	root := paths.add(-1, pathItem{target: 1, direction: engine.Any})
	two := paths.add(root, pathItem{target: 2, direction: engine.Out, combo: edgeCombo})
	three := paths.add(two, pathItem{target: 3, direction: engine.In, combo: edgeCombo})
	branch := paths.add(two, pathItem{target: 4, direction: engine.Out, combo: edgeCombo})
	filter := pathFilter(0).with(1).with(2).with(3)

	if !paths.hasNode(three, filter, 2) || !paths.hasNode(three, filter, 1) {
		t.Fatal("expected path to contain its earlier nodes")
	}
	if paths.hasNode(three, filter.with(4), 4) {
		t.Fatal("a sibling branch's node is not on this path")
	}
	if !paths.hasEdge(three, filter, 1, 2) {
		t.Fatal("expected path to contain 1->2 edge")
	}
	if !paths.hasEdge(three, filter, 3, 2) {
		t.Fatal("expected path to track reverse edge direction")
	}
	if paths.hasEdge(three, filter, 2, 3) {
		t.Fatal("edge direction ignored")
	}
	targets := func(tail int32) []engine.NodeIndex {
		var out []engine.NodeIndex
		for i := tail; i >= 0; i = paths.steps[i].parent {
			out = append([]engine.NodeIndex{paths.steps[i].item.target}, out...)
		}
		return out
	}
	if got := targets(branch); len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 4 {
		t.Fatalf("branch path %v", got)
	}
	// Extending one branch must not change another.
	if got := targets(three); len(got) != 3 || got[2] != 3 {
		t.Fatalf("shared prefix changed: %v", got)
	}
}

func TestPathFilter(t *testing.T) {
	var f pathFilter
	if f.mayHave(7) {
		t.Fatal("empty filter matched")
	}
	f = f.with(7)
	if !f.mayHave(7) {
		t.Fatal("added ID not found")
	}
}

func TestPathArenaCommitAndFlush(t *testing.T) {
	edgeAB := engine.NewEdge("unit-test-edge-ab")
	edgeBC := engine.NewEdge("unit-test-edge-bc")

	ao := engine.NewIndexedGraph()
	a := engine.NewNode(engine.Name, "A")
	b := engine.NewNode(engine.Name, "B")
	c := engine.NewNode(engine.Name, "C")
	enginetest.Add(ao, a)
	enginetest.Add(ao, b)
	enginetest.Add(ao, c)
	ia, _ := ao.NodeIndexOf(a)
	ib, _ := ao.NodeIndexOf(b)
	ic, _ := ao.NodeIndexOf(c)

	comboAB := ao.EdgeBitmapToEdgeCombo(engine.EdgeBitmap{}.Set(edgeAB))
	comboBC := ao.EdgeBitmapToEdgeCombo(engine.EdgeBitmap{}.Set(edgeBC))

	var paths pathArena
	root := paths.add(-1, pathItem{target: ia, direction: engine.Any, reference: 0})
	toB := paths.add(root, pathItem{target: ib, direction: engine.Out, combo: comboAB, reference: 1})
	toC := paths.add(toB, pathItem{target: ic, direction: engine.In, combo: comboBC, reference: 255})

	result := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()
	paths.commit(toB, ao, result)
	if !result.HasNode(a) || !result.HasNode(b) || result.HasNode(c) {
		t.Fatal("commit must add exactly the path's nodes immediately")
	}
	paths.commit(toC, ao, result)
	paths.flush(ao, result, []NodeQuery{{Reference: "start"}, {Reference: "middle"}})

	if reference := result.GetNodeData(a, "reference"); reference != "start" {
		t.Fatalf("expected node reference metadata, got %v", reference)
	}
	if reference := result.GetNodeData(b, "reference"); reference != "middle" {
		t.Fatalf("expected node reference metadata, got %v", reference)
	}
	if !result.HasEdge(a, b) || !result.HasEdge(c, b) {
		t.Fatal("expected forward and reverse edges to be committed")
	}
	flows := map[[2]*engine.Node]int{}
	result.IterateEdges(func(s, t *engine.Node, _ engine.EdgeBitmap, flow int) bool {
		flows[[2]*engine.Node{s, t}] = flow
		return true
	})
	if flows[[2]*engine.Node{a, b}] != 2 || flows[[2]*engine.Node{c, b}] != 1 {
		t.Fatalf("flow counts %v, want a->b used by both paths", flows)
	}
}

func BenchmarkPriorityQueuePushPop(b *testing.B) {
	queue := PriorityQueue{p: ShortestFirst}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		queue.Push(searchState{rank: uint32(i), currentTotalDepth: byte(i % 8)})
		_ = queue.Pop()
	}
}

func BenchmarkPathArenaExtend(b *testing.B) {
	var paths pathArena
	tail := paths.add(-1, pathItem{target: 1})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if len(paths.steps) > 1<<16 {
			paths.steps = paths.steps[:1]
			tail = 0
		}
		tail = paths.add(tail, pathItem{target: engine.NodeIndex(i + 2)})
	}
}

func TestPriorityQueuePopsInStrictOrder(t *testing.T) {
	queue := PriorityQueue{p: ProbableShortest}
	// Many ties on probability and depth; the order must still be total.
	var pushed []searchState
	for i := range 5000 {
		s := searchState{
			rank:                       uint32(i%37 + 1),
			path:                       int32(i),
			currentTotalDepth:          byte(i % 5),
			overAllProbabilityFraction: float32(i%3) / 2,
		}
		pushed = append(pushed, s)
		queue.Push(s)
	}
	ordered := PriorityQueue{p: ProbableShortest, items: pushed}
	sort.Slice(ordered.items, ordered.Less)
	for i := range ordered.items {
		if got := queue.Pop(); got != ordered.items[i] {
			t.Fatalf("pop %d: got %+v want %+v", i, got, ordered.items[i])
		}
	}
}
