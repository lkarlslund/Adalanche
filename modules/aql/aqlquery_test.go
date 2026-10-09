package aql

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func aqlFilterByName(name string) NodeQuery {
	return NodeQuery{
		Selector: query.FilterOneAttribute{
			Attribute: engine.Name,
			FilterAttribute: query.HasStringMatch{
				Value: engine.NV(name),
			},
		},
		Reference: name,
	}
}

func aqlEdgeMatcher(edge engine.Edge) EdgeMatcher {
	return EdgeMatcher{
		Bitmap:     engine.EdgeBitmap{}.Set(edge),
		Count:      1,
		Comparator: query.CompareGreaterThanEqual,
	}
}

func singleNodeGraph(node *engine.Node) *engine.IndexedGraph {
	graph := engine.NewIndexedGraph()
	enginetest.Add(graph, node)
	return graph
}

func TestAQLResolveSingleSourceAddsReference(t *testing.T) {
	alpha := engine.NewNode(engine.Name, "alpha")
	ao := engine.NewIndexedGraph()
	enginetest.Add(ao, alpha)

	resolver := AQLquery{
		datasource: ao,
		Sources: []NodeQuery{
			{
				Selector:  aqlFilterByName("alpha").Selector,
				Reference: "source",
			},
		},
	}

	result, err := resolver.Resolve(NewResolverOptions())
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if result.Order() != 1 || !result.HasNode(alpha) {
		t.Fatal("expected single source node in result graph")
	}
	if got := result.GetNodeData(alpha, "reference"); got != "source" {
		t.Fatalf("expected reference metadata, got %v", got)
	}
}

func TestAQLResolveWalkRequiresMaxIterationLimit(t *testing.T) {
	edgeType := engine.NewEdge("unit-test-walk-limit")
	alpha := engine.NewNode(engine.Name, "alpha")
	beta := engine.NewNode(engine.Name, "beta")
	ao := engine.NewIndexedGraph()
	enginetest.Add(ao, alpha)
	enginetest.Add(ao, beta)
	enginetest.Edge(ao, alpha, beta, edgeType)

	resolver := AQLquery{
		datasource: ao,
		Mode:       Walk,
		Sources:    []NodeQuery{aqlFilterByName("alpha"), aqlFilterByName("beta")},
		Next: []EdgeSearcher{{
			FilterEdges:   aqlEdgeMatcher(edgeType),
			Direction:     engine.Out,
			MinIterations: 1,
			MaxIterations: 0,
		}},
	}

	_, err := resolver.Resolve(NewResolverOptions())
	if err == nil {
		t.Fatal("expected walk mode without max iteration limit to fail")
	}
}

func TestAQLResolveTrailBlocksReusingSameEdgeInReverse(t *testing.T) {
	edgeType := engine.NewEdge("unit-test-trail-reuse")
	alpha := engine.NewNode(engine.Name, "alpha")
	beta := engine.NewNode(engine.Name, "beta")
	ao := engine.NewIndexedGraph()
	enginetest.Add(ao, alpha)
	enginetest.Add(ao, beta)
	enginetest.Edge(ao, alpha, beta, edgeType)

	newResolver := func(mode QueryMode) AQLquery {
		return AQLquery{
			datasource: ao,
			Mode:       mode,
			Traversal:  ShortestFirst,
			Sources:    []NodeQuery{aqlFilterByName("alpha"), aqlFilterByName("alpha")},
			sourceCache: []*engine.IndexedGraph{
				singleNodeGraph(alpha),
				singleNodeGraph(alpha),
			},
			Next: []EdgeSearcher{{
				FilterEdges:   aqlEdgeMatcher(edgeType),
				Direction:     engine.Any,
				MinIterations: 2,
				MaxIterations: 2,
			}},
		}
	}

	walkResult := searchFrom(newResolver(Walk), alpha)
	if walkResult.Order() != 2 || !walkResult.HasEdge(alpha, beta) || walkResult.HasEdge(beta, alpha) {
		t.Fatalf("expected walk mode to traverse the same stored edge out and back, got order=%d hasAB=%v hasBA=%v", walkResult.Order(), walkResult.HasEdge(alpha, beta), walkResult.HasEdge(beta, alpha))
	}

	trailResult := searchFrom(newResolver(Trail), alpha)
	if trailResult.Order() != 0 {
		t.Fatalf("expected trail mode to reject reused edge path, got %d nodes", trailResult.Order())
	}
}

func TestAQLResolveAcyclicBlocksReturningToVisitedNode(t *testing.T) {
	edgeType := engine.NewEdge("unit-test-acyclic-cycle")
	alpha := engine.NewNode(engine.Name, "alpha")
	beta := engine.NewNode(engine.Name, "beta")
	ao := engine.NewIndexedGraph()
	enginetest.Add(ao, alpha)
	enginetest.Add(ao, beta)
	enginetest.Edge(ao, alpha, beta, edgeType)
	enginetest.Edge(ao, beta, alpha, edgeType)

	newResolver := func(mode QueryMode) AQLquery {
		return AQLquery{
			datasource: ao,
			Mode:       mode,
			Traversal:  ShortestFirst,
			Sources:    []NodeQuery{aqlFilterByName("alpha"), aqlFilterByName("alpha")},
			sourceCache: []*engine.IndexedGraph{
				singleNodeGraph(alpha),
				singleNodeGraph(alpha),
			},
			Next: []EdgeSearcher{{
				FilterEdges:   aqlEdgeMatcher(edgeType),
				Direction:     engine.Out,
				MinIterations: 2,
				MaxIterations: 2,
			}},
		}
	}

	walkResult := searchFrom(newResolver(Walk), alpha)
	if !walkResult.HasEdge(alpha, beta) || !walkResult.HasEdge(beta, alpha) {
		t.Fatalf("expected walk mode to allow cycle path, got order=%d hasAB=%v hasBA=%v", walkResult.Order(), walkResult.HasEdge(alpha, beta), walkResult.HasEdge(beta, alpha))
	}

	acyclicResult := searchFrom(newResolver(Acyclic), alpha)
	if acyclicResult.Order() != 0 {
		t.Fatalf("expected acyclic mode to reject cycle, got %d nodes", acyclicResult.Order())
	}
}

func TestAQLResolveMinIterationsZeroAllowsZeroHopMatch(t *testing.T) {
	edgeType := engine.NewEdge("unit-test-zero-hop")
	alpha := engine.NewNode(engine.Name, "alpha")
	beta := engine.NewNode(engine.Name, "beta")
	ao := engine.NewIndexedGraph()
	enginetest.Add(ao, alpha)
	enginetest.Add(ao, beta)
	enginetest.Edge(ao, alpha, beta, edgeType)

	resolver := AQLquery{
		datasource: ao,
		Mode:       Acyclic,
		Traversal:  ShortestFirst,
		Sources:    []NodeQuery{aqlFilterByName("alpha"), aqlFilterByName("alpha")},
		sourceCache: []*engine.IndexedGraph{
			singleNodeGraph(alpha),
			singleNodeGraph(alpha),
		},
		Next: []EdgeSearcher{{
			FilterEdges:   aqlEdgeMatcher(edgeType),
			Direction:     engine.Out,
			MinIterations: 0,
			MaxIterations: 1,
		}},
	}

	result := searchFrom(resolver, alpha)
	if result.Order() != 1 || !result.HasNode(alpha) {
		t.Fatal("expected zero-hop resolution to commit the start node")
	}
	if result.HasEdge(alpha, beta) {
		t.Fatal("expected zero-hop path not to include traversed edge")
	}
}

func BenchmarkCommitToGraph(b *testing.B) {
	edgeType := engine.NewEdge("unit-test-bench-commit")
	ao := engine.NewIndexedGraph()
	nodes := make([]*engine.Node, 64)
	for i := range nodes {
		nodes[i] = engine.NewNode(engine.Name, "node-"+engine.NV(i).String())
		enginetest.Add(ao, nodes[i])
	}

	combo := ao.EdgeBitmapToEdgeCombo(engine.EdgeBitmap{}.Set(edgeType))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var paths pathArena
		tail := int32(-1)
		for j, node := range nodes {
			reference := byte(255)
			if j == 0 {
				reference = 0
			}
			index, _ := ao.NodeIndexOf(node)
			tail = paths.add(tail, pathItem{target: index, direction: engine.Out, combo: combo, reference: reference})
		}
		graphResult := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()
		paths.commit(tail, ao, graphResult)
		paths.flush(ao, graphResult, []NodeQuery{{Reference: "source"}})
	}
}

func disableProgressForBenchmark(b *testing.B) {
	b.Helper()

	previous := ui.ProgressEnabled()
	ui.SetProgressEnabled(false)
	b.Cleanup(func() {
		ui.SetProgressEnabled(previous)
	})
}

func BenchmarkResolveSmallAcyclic(b *testing.B) {
	disableProgressForBenchmark(b)

	edgeType := engine.NewEdge("unit-test-bench-resolve-small")
	ao := engine.NewIndexedGraph()
	alpha := engine.NewNode(engine.Name, "alpha")
	beta := engine.NewNode(engine.Name, "beta")
	gamma := engine.NewNode(engine.Name, "gamma")
	enginetest.Add(ao, alpha)
	enginetest.Add(ao, beta)
	enginetest.Add(ao, gamma)
	enginetest.Edge(ao, alpha, beta, edgeType)
	enginetest.Edge(ao, beta, gamma, edgeType)

	resolver := AQLquery{
		datasource: ao,
		Mode:       Acyclic,
		Traversal:  ShortestFirst,
		Sources:    []NodeQuery{aqlFilterByName("alpha"), aqlFilterByName("gamma")},
		Next: []EdgeSearcher{{
			FilterEdges:   aqlEdgeMatcher(edgeType),
			Direction:     engine.Out,
			MinIterations: 2,
			MaxIterations: 2,
		}},
	}

	opts := NewResolverOptions()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := resolver.Resolve(opts); err != nil {
			b.Fatalf("resolve failed: %v", err)
		}
	}
}

func BenchmarkResolveHubGraph(b *testing.B) {
	disableProgressForBenchmark(b)

	edgeType := engine.NewEdge("unit-test-bench-resolve-hub")
	ao := engine.NewIndexedGraph()
	hub := engine.NewNode(engine.Name, "hub")
	enginetest.Add(ao, hub)
	for i := 0; i < 128; i++ {
		node := engine.NewNode(engine.Name, "leaf-"+engine.NV(i).String())
		enginetest.Add(ao, node)
		enginetest.Edge(ao, hub, node, edgeType)
	}

	resolver := AQLquery{
		datasource: ao,
		Mode:       Walk,
		Traversal:  ShortestFirst,
		Sources:    []NodeQuery{aqlFilterByName("hub"), {Selector: nil}},
		Next: []EdgeSearcher{{
			FilterEdges:   aqlEdgeMatcher(edgeType),
			Direction:     engine.Out,
			MinIterations: 1,
			MaxIterations: 1,
		}},
	}

	opts := NewResolverOptions()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := resolver.Resolve(opts); err != nil {
			b.Fatalf("resolve failed: %v", err)
		}
	}
}

func searchFrom(q AQLquery, start *engine.Node) graph.Graph[*engine.Node, engine.EdgeBitmap] {
	g, _ := q.resolveEdgesFrom(NewResolverOptions(), start, q.datasource.RankedAdjacency(), engine.NewRouteChecker(q.datasource))
	return g
}
