package frontend

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	graphpkg "github.com/lkarlslund/adalanche/modules/graph"
)

func TestGenerateCytoscapeJSUsesNodeIDsForElementIDs(t *testing.T) {
	source := engine.NewNode(engine.Name, engine.NV("source"))
	target := engine.NewNode(engine.Name, engine.NV("target"))

	g := engine.NewIndexedGraph()
	enginetest.Add(g, source)
	enginetest.Add(g, target)
	enginetest.EdgeTo(g, source, target, engine.NewEdge("unit-test-export"))

	result := graphpkg.NewGraph[*engine.Node, engine.EdgeBitmap]()
	result.AddNode(source)
	result.AddNode(target)
	result.AddEdge(source, target, engine.EdgeBitmap{}.Set(engine.NewEdge("unit-test-export")))

	cyto, err := GenerateCytoscapeJS(g, result, false)
	if err != nil {
		t.Fatalf("GenerateCytoscapeJS returned error: %v", err)
	}

	var foundSource, foundTarget, foundEdge bool
	wantSourceID := "n" + fmt.Sprint(source.ID())
	wantTargetID := "n" + fmt.Sprint(target.ID())
	wantEdgeID := "e" + fmt.Sprint(source.ID()) + "-" + fmt.Sprint(target.ID())

	for _, element := range cyto.Elements {
		switch element.Group {
		case "nodes":
			switch element.Data.(MapStringInterface)["id"] {
			case wantSourceID:
				foundSource = true
			case wantTargetID:
				foundTarget = true
			}
		case "edges":
			edge := element.Data.(*CytoEdgeData)
			if edge.ID != wantEdgeID {
				continue
			}
			foundEdge = true
			if got := edge.Source; got != wantSourceID {
				t.Fatalf("edge source = %v, want %v", got, wantSourceID)
			}
			if got := edge.Target; got != wantTargetID {
				t.Fatalf("edge target = %v, want %v", got, wantTargetID)
			}
		}
	}

	if !foundSource {
		t.Fatalf("source node %q not found in export", wantSourceID)
	}
	if !foundTarget {
		t.Fatalf("target node %q not found in export", wantTargetID)
	}
	if !foundEdge {
		t.Fatalf("edge %q not found in export", wantEdgeID)
	}
}

// With shared combos, edges with the same edge types refer to one entry, and
// the entry lists the same types an inline export does.
func TestGenerateCytoscapeJSSharesEdgeCombos(t *testing.T) {
	first, second := engine.NewEdge("unit-test-combo-a"), engine.NewEdge("unit-test-combo-b")
	both := engine.EdgeBitmap{}.Set(first).Set(second)
	nodes := make([]*engine.Node, 4)
	g := engine.NewIndexedGraph()
	result := graphpkg.NewGraph[*engine.Node, engine.EdgeBitmap]()
	for i := range nodes {
		nodes[i] = engine.NewNode(engine.Name, engine.NV(fmt.Sprintf("combo%d", i)))
		enginetest.Add(g, nodes[i])
		result.AddNode(nodes[i])
	}
	result.AddEdge(nodes[0], nodes[1], both)
	result.AddEdge(nodes[2], nodes[3], both)
	result.AddEdge(nodes[1], nodes[2], engine.EdgeBitmap{}.Set(first))

	inline, err := GenerateCytoscapeJS(g, result, false)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := GenerateCytoscapeJS(g, result, true)
	if err != nil {
		t.Fatal(err)
	}
	if inline.EdgeCombos != nil {
		t.Fatal("inline export has a combo table")
	}
	if len(shared.EdgeCombos) != 2 {
		t.Fatalf("got %d combos, want 2", len(shared.EdgeCombos))
	}
	methods := map[string]string{}
	for _, element := range inline.Elements {
		if element.Group == "edges" {
			edge := element.Data.(*CytoEdgeData)
			if edge.Combo != nil {
				t.Fatal("inline export refers to a combo")
			}
			names := slices.Clone(edge.Methods)
			slices.Sort(names)
			methods[edge.ID] = fmt.Sprint(names)
		}
	}
	for _, element := range shared.Elements {
		if element.Group != "edges" {
			continue
		}
		edge := element.Data.(*CytoEdgeData)
		if edge.Methods != nil {
			t.Fatal("shared export lists methods on an edge")
		}
		if got := fmt.Sprint(shared.EdgeCombos[*edge.Combo]); got != methods[edge.ID] {
			t.Fatalf("edge %s: combo lists %s, inline export %s", edge.ID, got, methods[edge.ID])
		}
	}
}

// The web service encodes elements as encoding/json would.
func TestCytoscapeJSONMatchesStandardEncoding(t *testing.T) {
	source := engine.NewNode(engine.Name, engine.NV("json-source"))
	target := engine.NewNode(engine.Name, engine.NV("json-target <&>"))
	g := engine.NewIndexedGraph()
	result := graphpkg.NewGraph[*engine.Node, engine.EdgeBitmap]()
	for _, n := range []*engine.Node{source, target} {
		enginetest.Add(g, n)
		result.AddNode(n)
	}
	result.AddEdge(source, target, engine.EdgeBitmap{}.Set(engine.NewEdge("unit-test-json")))
	for _, shared := range []bool{false, true} {
		cyto, err := GenerateCytoscapeJS(g, result, shared)
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(cyto)
		if err != nil {
			t.Fatal(err)
		}
		got, err := JSON.Marshal(cyto)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("shared=%v: web service JSON\n%s\nencoding/json\n%s", shared, got, want)
		}
	}
}
