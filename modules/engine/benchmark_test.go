package engine

import "testing"

func BenchmarkGraphAddNodes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		for j := 0; j < 1000; j++ {
			graph.Add(benchmarkNamedNode(j))
		}
	}
}

func BenchmarkGraphAddEdges(b *testing.B) {
	edgeType := testEdge("bench-edge-add")
	graph := NewIndexedGraph()
	nodes := make([]*Node, 1024)
	for i := range nodes {
		nodes[i] = benchmarkNamedNode(i)
		graph.Add(nodes[i])
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		from := nodes[i%len(nodes)]
		to := nodes[(i+1)%len(nodes)]
		graph.EdgeToEx(from, to, edgeType, true)
	}
}

func BenchmarkGraphBulkLoadEdges(b *testing.B) {
	edgeType := testEdge("bench-bulk-edge")
	graph := NewIndexedGraph()
	nodes := make([]*Node, 1024)
	for i := range nodes {
		nodes[i] = benchmarkNamedNode(i)
		graph.Add(nodes[i])
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !graph.BulkLoadEdges(true) {
			b.Fatal("expected bulk loading to enable")
		}
		for j := 0; j < len(nodes)-1; j++ {
			graph.EdgeToEx(nodes[j], nodes[j+1], edgeType, true)
		}
		if !graph.BulkLoadEdges(false) {
			b.Fatal("expected bulk loading to disable")
		}
	}
}

func BenchmarkGetIndexWarm(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.Add(benchmarkNamedNode(i))
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
			graph.Add(benchmarkNamedNode(j))
		}
		_ = graph.GetIndex(Name)
	}
}

func BenchmarkGetMultiIndexWarm(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.Add(benchmarkNamedNode(i))
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
			graph.Add(benchmarkNamedNode(j))
		}
		_ = graph.GetMultiIndex(Name, SAMAccountName)
	}
}

func BenchmarkGetEdge(b *testing.B) {
	edgeType := testEdge("bench-edge-get")
	graph := NewIndexedGraph()
	from := benchmarkNamedNode(1)
	to := benchmarkNamedNode(2)
	graph.Add(from)
	graph.Add(to)
	graph.EdgeToEx(from, to, edgeType, true)

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
		_, _ = graph.FindMultiOrAdd(Name, NV("node"), func() *Node {
			return benchmarkNamedNode(i)
		})
	}
}

func BenchmarkFindOrAddHit(b *testing.B) {
	graph := NewIndexedGraph()
	node := benchmarkNamedNode(1)
	graph.Add(node)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = graph.FindOrAdd(Name, NV("node-1"))
	}
}

func BenchmarkFindOrAddMiss(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		_, _ = graph.FindOrAdd(Name, NV("node"), SAMAccountName, NV("NODE"))
	}
}

func BenchmarkFindTwoMultiOrAdd(b *testing.B) {
	graph := NewIndexedGraph()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = graph.FindTwoMultiOrAdd(Name, NV("node"), SAMAccountName, NV("node"), func() *Node {
			return NewNode(Name, NV("node"), SAMAccountName, NV("NODE"))
		})
	}
}

func BenchmarkFindTwoMultiOrAddHit(b *testing.B) {
	graph := NewIndexedGraph()
	node := NewNode(Name, NV("node"), SAMAccountName, NV("NODE"))
	graph.Add(node)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = graph.FindTwoMultiOrAdd(Name, NV("node"), SAMAccountName, NV("node"), nil)
	}
}

func BenchmarkFindTwoMultiOrAddMiss(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		_, _ = graph.FindTwoMultiOrAdd(Name, NV("node"), SAMAccountName, NV("node"), func() *Node {
			return NewNode(Name, NV("node"), SAMAccountName, NV("NODE"))
		})
	}
}

func BenchmarkGraphIterate(b *testing.B) {
	graph := NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.Add(benchmarkNamedNode(i))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph.Iterate(func(*Node) bool {
			return true
		})
	}
}

func BenchmarkAddRelaxed(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph := NewIndexedGraph()
		for j := 0; j < 1000; j++ {
			graph.AddRelaxed(benchmarkNamedNode(j))
		}
	}
}

func BenchmarkSetEdgeMerge(b *testing.B) {
	first := testEdge("bench-edge-merge-first")
	second := testEdge("bench-edge-merge-second")
	graph := NewIndexedGraph()
	from := benchmarkNamedNode(1)
	to := benchmarkNamedNode(2)
	graph.Add(from)
	graph.Add(to)
	graph.SetEdge(from, to, EdgeBitmap{}.Set(first), false)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		graph.SetEdge(from, to, EdgeBitmap{}.Set(second), true)
	}
}

func BenchmarkNodeSetFlex(b *testing.B) {
	node := NewNode()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node.SetFlex(
			IgnoreBlanks,
			Name, "Alpha",
			DisplayName, "Alpha Node",
			Description, "Node Description",
			SAMAccountName, "ALPHA",
		)
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
		graph.Add(node)
	}
}

func BenchmarkNodeSet(b *testing.B) {
	node := NewNode()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		node.Set(DisplayName, NV("Display"))
		node.Set(Description, NV("Description"))
	}
}
