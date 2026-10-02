package frontend

import (
	"fmt"
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
			switch element.Data["id"] {
			case wantSourceID:
				foundSource = true
			case wantTargetID:
				foundTarget = true
			}
		case "edges":
			if element.Data["id"] != wantEdgeID {
				continue
			}
			foundEdge = true
			if got := element.Data["source"]; got != wantSourceID {
				t.Fatalf("edge source = %v, want %v", got, wantSourceID)
			}
			if got := element.Data["target"]; got != wantTargetID {
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
