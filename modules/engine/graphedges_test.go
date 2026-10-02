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

	graph.edgeTo(from, to, canControl)

	edge, found := graph.GetEdge(from, to)
	if !found || !edge.IsSet(canControl) {
		t.Fatal("expected edge to be stored")
	}
	if graph.Edges(to, In).Len() != 1 {
		t.Fatal("expected reverse inbound edge to be visible")
	}

	graph.edgeClear(from, to, canControl)
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

	graph.edgeTo(node, node, edgeType)
	if graph.Edges(node, Out).Len() != 0 {
		t.Fatal("expected self-loop to be ignored")
	}

	graph.edgeTo(node, peer, edgeType)
	if graph.Edges(node, Out).Len() != 0 {
		t.Fatal("expected same-SID edge to be ignored without force")
	}

	graph.edgeToEx(node, peer, edgeType, true)
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

	graph.setEdge(from, to, EdgeBitmap{}.Set(first), false)
	graph.setEdge(from, to, EdgeBitmap{}.Set(second), true)

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

	graph.setEdge(from, to, EdgeBitmap{}.Set(first), false)
	graph.setEdge(from, to, EdgeBitmap{}.Set(second), false)

	edge, found := graph.GetEdge(from, to)
	if !found {
		t.Fatal("expected overwritten edge to exist")
	}
	if edge.IsSet(first) || !edge.IsSet(second) {
		t.Fatalf("expected overwrite to replace prior bitmap, got %v", edge.Edges())
	}

	graph.setEdge(from, to, EdgeBitmap{}, false)
	edge, found = graph.GetEdge(from, to)
	if found || !edge.IsBlank() {
		t.Fatal("expected blank bitmap to remove edge")
	}

	graph.setEdge(from, to, EdgeBitmap{}, false)
	edge, found = graph.GetEdge(from, to)
	if found || !edge.IsBlank() {
		t.Fatal("expected repeated blank overwrite to remain removed")
	}
}

func TestEdgeImporterCommitAppliesBufferedEdges(t *testing.T) {
	first := testEdge("bulk-first")
	second := testEdge("bulk-second")
	from := testNamedNode("from")
	to := testNamedNode("to")
	graph := testGraph(from, to)
	importer := NewEdgeImporter(2)

	importer.Add(from, to, first, false)
	importer.Set(from, to, EdgeBitmap{}.Set(second), true)
	importer.Commit(graph)

	edge, found := graph.GetEdge(from, to)
	if !found || !edge.IsSet(first) || !edge.IsSet(second) {
		t.Fatal("expected buffered importer edge updates to be applied")
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
				graph.edgeToEx(from, to, canControl, true)
				_, _ = graph.GetEdge(from, to)
			}
		}(i)
	}
	wg.Wait()

	if graph.Size() == 0 {
		t.Fatal("expected concurrent writers to produce edges")
	}
}
