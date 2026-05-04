package query

import (
	"testing"

	"github.com/gobwas/glob"
	"github.com/lkarlslund/adalanche/modules/engine"
)

func TestNodeFilterExecuteUsesIndexWhenAvailable(t *testing.T) {
	t.Parallel()

	alpha := engine.NewNode(engine.Name, "Alpha")
	beta := engine.NewNode(engine.Name, "Beta")
	graph := engine.NewIndexedGraph()
	graph.Add(alpha)
	graph.Add(beta)

	result := NodeFilterExecute(FilterOneAttribute{
		Attribute: engine.Name,
		FilterAttribute: HasStringMatch{
			Value: engine.NV("alpha"),
		},
	}, graph)

	if result.Order() != 1 || !result.Contains(alpha) || result.Contains(beta) {
		t.Fatal("expected index-backed equality filter to return only alpha")
	}
}

func TestNodeFilterExecuteFallsBackForNonIndexedFilter(t *testing.T) {
	t.Parallel()

	alpha := engine.NewNode(engine.Name, "Alpha")
	beta := engine.NewNode(engine.Name, "Beta")
	graph := engine.NewIndexedGraph()
	graph.Add(alpha)
	graph.Add(beta)

	result := NodeFilterExecute(FilterOneAttribute{
		Attribute: engine.Name,
		FilterAttribute: HasGlobMatch{
			Match:   glob.MustCompile("b*"),
			Globstr: "b*",
		},
	}, graph)

	if result.Order() != 1 || !result.Contains(beta) || result.Contains(alpha) {
		t.Fatal("expected non-indexed glob filter to fall back to evaluation")
	}
}
