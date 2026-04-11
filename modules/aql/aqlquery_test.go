package aql

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
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
	graph.Add(node)
	return graph
}

func TestAQLResolveSingleSourceAddsReference(t *testing.T) {
	alpha := engine.NewNode(engine.Name, "alpha")
	ao := engine.NewIndexedGraph()
	ao.Add(alpha)

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
	ao.Add(alpha)
	ao.Add(beta)
	ao.EdgeToEx(alpha, beta, edgeType, true)

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
	ao.Add(alpha)
	ao.Add(beta)
	ao.EdgeToEx(alpha, beta, edgeType, true)

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

	walkResult := newResolver(Walk).resolveEdgesFrom(NewResolverOptions(), alpha)
	if walkResult.Order() != 2 || !walkResult.HasEdge(alpha, beta) || walkResult.HasEdge(beta, alpha) {
		t.Fatalf("expected walk mode to traverse the same stored edge out and back, got order=%d hasAB=%v hasBA=%v", walkResult.Order(), walkResult.HasEdge(alpha, beta), walkResult.HasEdge(beta, alpha))
	}

	trailResult := newResolver(Trail).resolveEdgesFrom(NewResolverOptions(), alpha)
	if trailResult.Order() != 0 {
		t.Fatalf("expected trail mode to reject reused edge path, got %d nodes", trailResult.Order())
	}
}

func TestAQLResolveAcyclicBlocksReturningToVisitedNode(t *testing.T) {
	edgeType := engine.NewEdge("unit-test-acyclic-cycle")
	alpha := engine.NewNode(engine.Name, "alpha")
	beta := engine.NewNode(engine.Name, "beta")
	ao := engine.NewIndexedGraph()
	ao.Add(alpha)
	ao.Add(beta)
	ao.EdgeToEx(alpha, beta, edgeType, true)
	ao.EdgeToEx(beta, alpha, edgeType, true)

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

	walkResult := newResolver(Walk).resolveEdgesFrom(NewResolverOptions(), alpha)
	if !walkResult.HasEdge(alpha, beta) || !walkResult.HasEdge(beta, alpha) {
		t.Fatalf("expected walk mode to allow cycle path, got order=%d hasAB=%v hasBA=%v", walkResult.Order(), walkResult.HasEdge(alpha, beta), walkResult.HasEdge(beta, alpha))
	}

	acyclicResult := newResolver(Acyclic).resolveEdgesFrom(NewResolverOptions(), alpha)
	if acyclicResult.Order() != 0 {
		t.Fatalf("expected acyclic mode to reject cycle, got %d nodes", acyclicResult.Order())
	}
}

func TestAQLResolveMinIterationsZeroAllowsZeroHopMatch(t *testing.T) {
	edgeType := engine.NewEdge("unit-test-zero-hop")
	alpha := engine.NewNode(engine.Name, "alpha")
	beta := engine.NewNode(engine.Name, "beta")
	ao := engine.NewIndexedGraph()
	ao.Add(alpha)
	ao.Add(beta)
	ao.EdgeToEx(alpha, beta, edgeType, true)

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

	result := resolver.resolveEdgesFrom(NewResolverOptions(), alpha)
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
		ao.Add(nodes[i])
	}

	combo := ao.EdgeBitmapToEdgeCombo(engine.EdgeBitmap{}.Set(edgeType))
	var path probableWorkingPath
	for i, node := range nodes {
		reference := byte(255)
		if i == 0 {
			reference = 0
		}
		path.Add(node.ID(), engine.Out, combo, reference)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graphResult := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()
		path.CommitToGraph(ao, graphResult, []NodeQuery{{Reference: "source"}})
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
	ao.Add(alpha)
	ao.Add(beta)
	ao.Add(gamma)
	ao.EdgeToEx(alpha, beta, edgeType, true)
	ao.EdgeToEx(beta, gamma, edgeType, true)

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
	ao.Add(hub)
	for i := 0; i < 128; i++ {
		node := engine.NewNode(engine.Name, "leaf-"+engine.NV(i).String())
		ao.Add(node)
		ao.EdgeToEx(hub, node, edgeType, true)
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
