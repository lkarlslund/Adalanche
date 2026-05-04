package engine

import (
	"sync"
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestIndexedGraphEdgeRoundTripAndClear(t *testing.T) {
	canControl := testEdge("can-control")
	from := testNamedNode("from")
	to := testNamedNode("to")
	graph := testGraph(from, to)

	graph.EdgeTo(from, to, canControl)

	edge, found := graph.GetEdge(from, to)
	if !found || !edge.IsSet(canControl) {
		t.Fatal("expected edge to be stored")
	}
	if graph.Edges(to, In).Len() != 1 {
		t.Fatal("expected reverse inbound edge to be visible")
	}

	graph.EdgeClear(from, to, canControl)
	edge, found = graph.GetEdge(from, to)
	if found || !edge.IsBlank() {
		t.Fatal("expected cleared edge to be removed")
	}
	if graph.Edges(to, In).Len() != 0 {
		t.Fatal("expected reverse inbound edge to be cleared")
	}
}

func TestIndexedGraphEdgeSkipsSelfLoopsAndSameSIDUnlessForced(t *testing.T) {
	edgeType := testEdge("self-loop")
	sid := windowssecurity.SID("S-1-5-21-1-2-3-4")
	node := testNode(Name, "self", ObjectSid, sid)
	peer := testNode(Name, "peer", ObjectSid, sid)
	graph := testGraph(node, peer)

	graph.EdgeTo(node, node, edgeType)
	if graph.Edges(node, Out).Len() != 0 {
		t.Fatal("expected self-loop to be ignored")
	}

	graph.EdgeTo(node, peer, edgeType)
	if graph.Edges(node, Out).Len() != 0 {
		t.Fatal("expected same-SID edge to be ignored without force")
	}

	graph.EdgeToEx(node, peer, edgeType, true)
	edge, found := graph.GetEdge(node, peer)
	if !found || !edge.IsSet(edgeType) {
		t.Fatal("expected forced same-SID edge to be stored")
	}
}

func TestIndexedGraphSetEdgeMerge(t *testing.T) {
	first := testEdge("first")
	second := testEdge("second")
	from := testNamedNode("from")
	to := testNamedNode("to")
	graph := testGraph(from, to)

	graph.SetEdge(from, to, EdgeBitmap{}.Set(first), false)
	graph.SetEdge(from, to, EdgeBitmap{}.Set(second), true)

	edge, found := graph.GetEdge(from, to)
	if !found {
		t.Fatal("expected merged edge to exist")
	}
	if !edge.IsSet(first) || !edge.IsSet(second) {
		t.Fatal("expected merged edge bitmap to contain both edges")
	}
}

func TestIndexedGraphSetEdgeOverwriteAndBlankRemoval(t *testing.T) {
	first := testEdge("overwrite-first")
	second := testEdge("overwrite-second")
	from := testNamedNode("from")
	to := testNamedNode("to")
	graph := testGraph(from, to)

	graph.SetEdge(from, to, EdgeBitmap{}.Set(first), false)
	graph.SetEdge(from, to, EdgeBitmap{}.Set(second), false)

	edge, found := graph.GetEdge(from, to)
	if !found {
		t.Fatal("expected overwritten edge to exist")
	}
	if edge.IsSet(first) || !edge.IsSet(second) {
		t.Fatalf("expected overwrite to replace prior bitmap, got %v", edge.Edges())
	}

	graph.SetEdge(from, to, EdgeBitmap{}, false)
	edge, found = graph.GetEdge(from, to)
	if found || !edge.IsBlank() {
		t.Fatal("expected blank bitmap to remove edge")
	}

	graph.SetEdge(from, to, EdgeBitmap{}, false)
	edge, found = graph.GetEdge(from, to)
	if found || !edge.IsBlank() {
		t.Fatal("expected repeated blank overwrite to remain removed")
	}
}

func TestIndexedGraphBulkLoadEdgesFlushesBufferedEdges(t *testing.T) {
	first := testEdge("bulk-first")
	second := testEdge("bulk-second")
	from := testNamedNode("from")
	to := testNamedNode("to")
	graph := testGraph(from, to)

	if !graph.BulkLoadEdges(true) {
		t.Fatal("expected bulk load enable to succeed")
	}
	graph.EdgeTo(from, to, first)
	graph.SetEdge(from, to, EdgeBitmap{}.Set(second), true)
	if !graph.FlushEdges() {
		t.Fatal("expected flush to succeed while bulk loading")
	}
	if !graph.BulkLoadEdges(false) {
		t.Fatal("expected bulk load disable to succeed")
	}

	edge, found := graph.GetEdge(from, to)
	if !found || !edge.IsSet(first) || !edge.IsSet(second) {
		t.Fatal("expected buffered bulk edge updates to be flushed")
	}
}

func TestIndexedGraphConcurrentEdgeWritesAndReads(t *testing.T) {
	canControl := testEdge("concurrent")
	nodes := make([]*Node, 0, 32)
	for i := range 32 {
		nodes = append(nodes, testNamedNode("node-"+NV(i).String()))
	}
	graph := testGraph(nodes...)

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := range 200 {
				from := nodes[(worker+j)%len(nodes)]
				to := nodes[(worker+j+1)%len(nodes)]
				graph.EdgeToEx(from, to, canControl, true)
				_, _ = graph.GetEdge(from, to)
			}
		}(i)
	}
	wg.Wait()

	if graph.Size() == 0 {
		t.Fatal("expected concurrent writers to produce edges")
	}
}
