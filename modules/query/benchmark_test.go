package query

import (
	"testing"

	"github.com/gobwas/glob"
	"github.com/lkarlslund/adalanche/modules/engine"
)

func benchmarkQueryGraph() *engine.IndexedGraph {
	graph := engine.NewIndexedGraph()
	for i := 0; i < 5000; i++ {
		graph.Add(engine.NewNode(
			engine.Name, "node-"+engine.NV(i).String(),
			engine.DisplayName, "Node",
		))
	}
	return graph
}

func BenchmarkNodeFilterExecuteIndexed(b *testing.B) {
	graph := benchmarkQueryGraph()
	filter := FilterOneAttribute{
		Attribute: engine.Name,
		FilterAttribute: HasStringMatch{
			Value: engine.NV("node-4242"),
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NodeFilterExecute(filter, graph)
	}
}

func BenchmarkNodeFilterExecuteFallback(b *testing.B) {
	graph := benchmarkQueryGraph()
	filter := FilterOneAttribute{
		Attribute: engine.Name,
		FilterAttribute: HasGlobMatch{
			Match:   glob.MustCompile("node-42*"),
			Globstr: "node-42*",
		},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NodeFilterExecute(filter, graph)
	}
}
