package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/opengraph"
)

// Edges connect the nodes their references match, by the attribute named in
// match_by with the reference's value.
func TestOpenGraphEdgesMatchNodesByValue(t *testing.T) {
	g := engine.NewIndexedGraph()
	model := opengraph.Model{Graph: opengraph.OpenGraph{
		Nodes: []opengraph.OpenGraphNode{
			{ID: "a", Kinds: []string{"Person"}, Properties: map[string]any{"name": "synthetic-a"}},
			{ID: "b", Kinds: []string{"Group"}, Properties: map[string]any{"name": "synthetic-b"}},
		},
		Edges: []opengraph.OpenGraphEdge{
			{Start: opengraph.OpenNodeReference{MatchBy: "id", Value: "a"}, End: opengraph.OpenNodeReference{MatchBy: "id", Value: "b"}, Kind: "SyntheticMemberOf"},
			{Start: opengraph.OpenNodeReference{MatchBy: "id", Value: "b"}, End: opengraph.OpenNodeReference{MatchBy: "id", Value: "c"}, Kind: "SyntheticMemberOf"},
		},
	}}
	tx := g.Begin("test")
	if err := processOpenGraphData(tx, model); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if g.Order() != 3 {
		t.Errorf("got %v nodes, want the two listed and one referenced", g.Order())
	}
	node := func(id string) *engine.Node {
		n, found := g.Find(attributeOpenGraphID, engine.NV(id))
		if !found {
			t.Fatalf("node %v missing", id)
		}
		return n
	}
	edge := engine.LookupEdge("SyntheticMemberOf")
	for _, pair := range [][2]string{{"a", "b"}, {"b", "c"}} {
		if eb, _ := g.GetEdge(node(pair[0]), node(pair[1])); !eb.IsSet(edge) {
			t.Errorf("no edge %v -> %v", pair[0], pair[1])
		}
	}
}
