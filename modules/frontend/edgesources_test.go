package frontend

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
)

func TestEdgeDetailsIncludeCauses(t *testing.T) {
	kind := engine.NewSourceKind("Frontend test")
	edge := engine.NewEdge("FrontendTestEdge")
	g := engine.NewIndexedGraph()
	tx := g.Begin("test")
	from, to, about := tx.AddNew(engine.Name, "from"), tx.AddNew(engine.Name, "to"), tx.AddNew(engine.Name, "policy")
	tx.EdgeBecause(from, to, edge, engine.Source{Kind: kind, About: about, Detail: "setting"})
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	details, found := apiEdgeDetails(g, from.Node(), to.Node())
	if !found || len(details.Sources) != 1 {
		t.Fatalf("got %+v", details.Sources)
	}
	s := details.Sources[0]
	if s.Edge != "FrontendTestEdge" || s.Kind != "Frontend test" || s.Detail != "setting" || s.About == nil || s.About.ID != about.Node().ID() || s.SetOn == nil || s.SetOn.ID != about.Node().ID() {
		t.Fatalf("got %+v", s)
	}
}
