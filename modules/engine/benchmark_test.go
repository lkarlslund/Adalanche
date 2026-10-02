package engine

import (
	"fmt"
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func BenchmarkGraphAddNodes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		for j := 0; j < 1000; j++ {
			graph.add(benchmarkNamedNode(j))
		}
	}
}

func BenchmarkGraphAddEdges(b *testing.B) {
	edgeType := testEdge("bench-edge-add")
	graph := NewIndexedGraph()
	nodes := make([]*Node, 1024)
	for i := range nodes {
		nodes[i] = benchmarkNamedNode(i)
		graph.add(nodes[i])
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		from := nodes[i%len(nodes)]
		to := nodes[(i+1)%len(nodes)]
		graph.edgeToEx(from, to, edgeType, true)
	}
}

func BenchmarkEdgeImporterCommit(b *testing.B) {
	edgeType := testEdge("bench-bulk-edge")
	nodes := make([]*Node, 1024)
	for i := range nodes {
		nodes[i] = benchmarkNamedNode(i)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		for _, node := range nodes {
			graph.add(node)
		}
		importer := NewEdgeImporter(len(nodes) - 1)
		for j := 0; j < len(nodes)-1; j++ {
			importer.Add(nodes[j], nodes[j+1], edgeType, true)
		}
		importer.Commit(graph)
	}
}

func BenchmarkGetIndexWarm(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.add(benchmarkNamedNode(i))
	}
	index := graph.GetIndex(Name)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = index.Lookup(NV("node-4242"))
	}
}

func BenchmarkGetIndexCold(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		for j := 0; j < 5000; j++ {
			graph.add(benchmarkNamedNode(j))
		}
		_ = graph.GetIndex(Name)
	}
}

func BenchmarkGetMultiIndexWarm(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.add(benchmarkNamedNode(i))
	}
	index := graph.GetMultiIndex(Name, SAMAccountName)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = index.Lookup(NV("node-4242"), NV("node-4242"))
	}
}

func BenchmarkGetMultiIndexCold(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		for j := 0; j < 5000; j++ {
			graph.add(benchmarkNamedNode(j))
		}
		_ = graph.GetMultiIndex(Name, SAMAccountName)
	}
}

func BenchmarkGetEdge(b *testing.B) {
	edgeType := testEdge("bench-edge-get")
	graph := NewIndexedGraph()
	from := benchmarkNamedNode(1)
	to := benchmarkNamedNode(2)
	graph.add(from)
	graph.add(to)
	graph.edgeToEx(from, to, edgeType, true)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = graph.GetEdge(from, to)
	}
}

func BenchmarkEdgeBitmapToEdgeCombo(b *testing.B) {
	graph := NewIndexedGraph()
	edgeType := testEdge("bench-edge-combo")
	other := testEdge("bench-edge-combo-other")
	bitmap := EdgeBitmap{}.Set(edgeType).Set(other)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = graph.EdgeBitmapToEdgeCombo(bitmap)
	}
}

func BenchmarkFindMultiOrAdd(b *testing.B) {
	graph := NewIndexedGraph()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = graph.findMultiOrAdd(Name, NV("node"), func() *Node {
			return benchmarkNamedNode(i)
		})
	}
}

func BenchmarkFindOrAddHit(b *testing.B) {
	graph := NewIndexedGraph()
	node := benchmarkNamedNode(1)
	graph.add(node)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = graph.findOrAdd(Name, NV("node-1"))
	}
}

func BenchmarkFindOrAddMiss(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		_, _ = graph.findOrAdd(Name, NV("node"), SAMAccountName, NV("NODE"))
	}
}

func BenchmarkFindTwoMultiOrAdd(b *testing.B) {
	graph := NewIndexedGraph()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = graph.findTwoMultiOrAdd(Name, NV("node"), SAMAccountName, NV("node"), func() *Node {
			return NewNode(Name, NV("node"), SAMAccountName, NV("NODE"))
		})
	}
}

func BenchmarkFindTwoMultiOrAddHit(b *testing.B) {
	graph := NewIndexedGraph()
	node := NewNode(Name, NV("node"), SAMAccountName, NV("NODE"))
	graph.add(node)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = graph.findTwoMultiOrAdd(Name, NV("node"), SAMAccountName, NV("node"), nil)
	}
}

func BenchmarkFindTwoMultiOrAddMiss(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		_, _ = graph.findTwoMultiOrAdd(Name, NV("node"), SAMAccountName, NV("node"), func() *Node {
			return NewNode(Name, NV("node"), SAMAccountName, NV("NODE"))
		})
	}
}

func benchmarkMustSID(value string) windowssecurity.SID {
	sid, err := windowssecurity.ParseStringSID(value)
	if err != nil {
		panic(err)
	}
	return sid
}

func BenchmarkFindOrAddAdjacentSIDFoundUniqueHit(b *testing.B) {
	graph := NewIndexedGraph()
	relative := NewNode(
		Name, NV("relative"),
		Type, NodeTypeUser.ValueString(),
		DomainContext, NV("DC=example,DC=com"),
		DataSource, NV("EXAMPLE"),
	)
	graph.add(relative)

	sid := benchmarkMustSID("S-1-5-21-111-222-333-444")
	existing := NewNode(
		Name, NV("existing"),
		ObjectSid, NV(sid),
	)
	graph.add(existing)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node, found := graph.findOrAddAdjacentSIDFound(sid, relative)
		if !found || node != existing {
			b.Fatal("expected existing global SID node")
		}
	}
}

func BenchmarkFindOrAddAdjacentSIDFoundMachineScopedHit(b *testing.B) {
	graph := NewIndexedGraph()
	machineSID := benchmarkMustSID("S-1-5-21-111-222-333-1000")
	accountSID := benchmarkMustSID("S-1-5-21-111-222-333-1001")
	relative := NewNode(
		Name, NV("machine"),
		Type, NodeTypeMachine.ValueString(),
		ObjectSid, NV(machineSID),
		DataSource, NV("HOST01"),
	)
	graph.add(relative)

	existing := NewNode(
		Name, NV("existing"),
		ObjectSid, NV(accountSID),
		DataSource, NV("HOST01"),
	)
	graph.add(existing)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node, found := graph.findOrAddAdjacentSIDFound(accountSID, relative)
		if !found || node != existing {
			b.Fatal("expected existing machine-scoped SID node")
		}
	}
}

func BenchmarkFindOrAddAdjacentSIDFoundMiss(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		relative := NewNode(
			Name, NV("relative"),
			Type, NodeTypeUser.ValueString(),
			DomainContext, NV("DC=example,DC=com"),
			DataSource, NV("EXAMPLE"),
		)
		graph.add(relative)

		sid := benchmarkMustSID(fmt.Sprintf("S-1-5-21-111-222-333-%d", 1000+i))
		node, found := graph.findOrAddAdjacentSIDFound(sid, relative)
		if found || node == nil {
			b.Fatal("expected synthetic SID node to be created")
		}
	}
}

func BenchmarkFindAdjacentSIDUniqueHit(b *testing.B) {
	graph := NewIndexedGraph()
	relative := NewNode(
		Name, NV("relative"),
		Type, NodeTypeUser.ValueString(),
		DomainContext, NV("DC=example,DC=com"),
		DataSource, NV("EXAMPLE"),
	)
	graph.add(relative)

	sid := benchmarkMustSID("S-1-5-21-111-222-333-444")
	existing := NewNode(
		Name, NV("existing"),
		ObjectSid, NV(sid),
	)
	graph.add(existing)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node, found := graph.FindAdjacentSID(sid, relative)
		if !found || node != existing {
			b.Fatal("expected existing global SID node")
		}
	}
}

func BenchmarkGraphIterate(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.add(benchmarkNamedNode(i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph.Iterate(func(*Node) bool {
			return true
		})
	}
}

func BenchmarkGraphIterateStable(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.add(benchmarkNamedNode(i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph.IterateStable(func(*Node) bool {
			return true
		})
	}
}

func BenchmarkGraphIterateParallelStable(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.add(benchmarkNamedNode(i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph.IterateParallelStable(func(*Node) bool {
			return true
		}, 0)
	}
}

func BenchmarkFrozenGraphFind(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.add(benchmarkNamedNode(i))
	}
	view := graph.freeze()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node, found := view.Find(Name, NV("node-4242"))
		if !found || node == nil {
			b.Fatal("expected node")
		}
	}
}

func BenchmarkFrozenGraphFindTwo(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.add(NewNode(
			Name, NV(fmt.Sprintf("node-%d", i)),
			SAMAccountName, NV(fmt.Sprintf("node-%d", i)),
		))
	}
	view := graph.freeze()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node, found := view.FindTwo(Name, NV("node-4242"), SAMAccountName, NV("node-4242"))
		if !found || node == nil {
			b.Fatal("expected node")
		}
	}
}

func BenchmarkFrozenGraphFindAdjacentSID(b *testing.B) {
	graph := NewIndexedGraph()
	relative := NewNode(
		Name, NV("relative"),
		Type, NodeTypeUser.ValueString(),
		DomainContext, NV("DC=example,DC=com"),
		DataSource, NV("EXAMPLE"),
	)
	graph.add(relative)

	sid := benchmarkMustSID("S-1-5-21-111-222-333-444")
	existing := NewNode(
		Name, NV("existing"),
		ObjectSid, NV(sid),
	)
	graph.add(existing)
	view := graph.freeze()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node, found := view.FindAdjacentSID(sid, relative)
		if !found || node != existing {
			b.Fatal("expected existing global SID node")
		}
	}
}

func BenchmarkFrozenGraphIterateLarge(b *testing.B) {
	graph := buildSyntheticGraph(largeSyntheticGraphConfig())
	view := graph.freeze()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		view.Iterate(func(*Node) bool {
			return true
		})
	}
}

func BenchmarkFreezeLarge(b *testing.B) {
	graph := buildSyntheticGraph(largeSyntheticGraphConfig())

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = graph.freeze()
	}
}

func BenchmarkFrozenGraphIterateEdgesLarge(b *testing.B) {
	graph := buildSyntheticGraph(largeSyntheticGraphConfig())
	view := graph.freeze()
	var source *Node
	view.Iterate(func(node *Node) bool {
		source = node
		return false
	})
	if source == nil {
		b.Fatal("expected source node")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		view.IterateEdges(source, Out, func(*Node, EdgeBitmap) bool {
			return true
		})
	}
}

func BenchmarkCalculateGraphValuesSyntheticIndexedGraph(b *testing.B) {
	graph := buildSyntheticGraph(mediumSyntheticGraphConfig())
	matchEdges := EdgeBitmap{}.
		Set(testEdge("synthetic-member")).
		Set(testEdge("synthetic-admin"))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CalculateGraphValues(graph, matchEdges, 0, "indexed synthetic", func(node *Node) int {
			return len(node.OneAttrString(Name)) % 5
		})
	}
}

func BenchmarkCalculateGraphValuesSyntheticFrozenGraph(b *testing.B) {
	graph := buildSyntheticGraph(mediumSyntheticGraphConfig())
	view := graph.freeze()
	matchEdges := EdgeBitmap{}.
		Set(testEdge("synthetic-member")).
		Set(testEdge("synthetic-admin"))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CalculateGraphValues(view, matchEdges, 0, "frozen synthetic", func(node *Node) int {
			return len(node.OneAttrString(Name)) % 5
		})
	}
}

func BenchmarkAddRelaxed(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		for j := 0; j < 1000; j++ {
			graph.addRelaxed(benchmarkNamedNode(j))
		}
	}
}

func BenchmarkSetEdgeMerge(b *testing.B) {
	first := testEdge("bench-edge-merge-first")
	second := testEdge("bench-edge-merge-second")
	graph := NewIndexedGraph()
	from := benchmarkNamedNode(1)
	to := benchmarkNamedNode(2)
	graph.add(from)
	graph.add(to)
	graph.setEdge(from, to, EdgeBitmap{}.Set(first), false)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph.setEdge(from, to, EdgeBitmap{}.Set(second), true)
	}
}

func BenchmarkNodeGet(b *testing.B) {
	node := NewNode(
		Name, NV("alpha"),
		Description, NV("desc"),
		SAMAccountName, NV("ALPHA"),
	)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, found := node.get(Name); !found {
			b.Fatal("expected attribute")
		}
	}
}

func BenchmarkAttributesAndValuesGet(b *testing.B) {
	node := NewNode(
		Name, NV("alpha"),
		Description, NV("desc"),
		SAMAccountName, NV("ALPHA"),
	)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, found := node.values.Get(Name); !found {
			b.Fatal("expected attribute")
		}
	}
}

func BenchmarkNodeSetFlex(b *testing.B) {
	node := NewNode()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node.setFlex(
			IgnoreBlanks,
			Name, "Alpha",
			DisplayName, "Alpha Node",
			Description, "Node Description",
			SAMAccountName, "ALPHA",
		)
	}
}

func BenchmarkTxCommitAttributeWrites(b *testing.B) {
	graph := NewIndexedGraph()
	nodes := make([]*Node, 1000)
	for i := range nodes {
		nodes[i] = benchmarkNamedNode(i)
		graph.add(nodes[i])
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tx := graph.Begin("bench")
		for _, node := range nodes {
			tx.Node(node).SetFlex(Description, NV("patched")).Tag("bench")
		}
		if err := tx.Commit(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReindexObject(b *testing.B) {
	graph := NewIndexedGraph()
	_ = graph.GetIndex(Name)
	_ = graph.GetIndex(SAMAccountName)
	_ = graph.GetMultiIndex(Name, SAMAccountName)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node := NewNode(
			Name, NV("node"),
			SAMAccountName, NV("NODE"),
		)
		graph.add(node)
	}
}

func BenchmarkNodeSet(b *testing.B) {
	node := NewNode()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node.set(DisplayName, NV("Display"))
		node.set(Description, NV("Description"))
	}
}
