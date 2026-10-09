package mcpserver

import (
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var (
	edgeDeniable = engine.NewEdge("MCPTestDeniable")
	deniedSID    = windowssecurity.SID("") // set by denyGraph
)

// denyStub refuses edgeDeniable to accounts named "denied".
type denyStub struct{}

func (denyStub) Refusers(_, _ *engine.Node, eb engine.EdgeBitmap) []engine.Refusal {
	if !eb.IsSet(edgeDeniable) {
		return nil
	}
	return []engine.Refusal{{Edge: edgeDeniable, Grants: [][]windowssecurity.SID{{deniedSID}}}}
}

func (denyStub) InToken(actor *engine.Node) func(windowssecurity.SID) bool {
	return func(s windowssecurity.SID) bool { return actor.Label() == "denied" && s == deniedSID }
}

func (denyStub) Holders(windowssecurity.SID, *engine.Node) []*engine.Node { return nil }

func init() {
	engine.RegisterActorChecker(func(*engine.IndexedGraph) engine.ActorChecker { return denyStub{} })
}

// denyGraph: an account reaches the target through a group whose edge a
// deny refuses to it, and through a longer route of two other nodes.
func denyGraph(t *testing.T) (*engine.IndexedGraph, map[string]*engine.Node) {
	t.Helper()
	deniedSID = mustSID(t, "S-1-5-21-1-2-3-1101")
	g := engine.NewIndexedGraph()
	nodes := map[string]*engine.Node{
		"denied": engine.NewNode(engine.Name, "denied", engine.Type, engine.NodeTypeUser.ValueString(), engine.ObjectSid, mustSID(t, "S-1-5-21-1-2-3-1201")),
		"group":  engine.NewNode(engine.Name, "group", engine.Type, engine.NodeTypeGroup.ValueString(), engine.ObjectSid, mustSID(t, "S-1-5-21-1-2-3-1102")),
		"other":  engine.NewNode(engine.Name, "other"),
		"other2": engine.NewNode(engine.Name, "other2"),
		"target": engine.NewNode(engine.Name, "target"),
	}
	for _, n := range nodes {
		enginetest.Add(g, n)
	}
	enginetest.Tag(g, nodes["target"], "hvt")
	enginetest.Edge(g, nodes["denied"], nodes["group"], edgeControls)
	enginetest.Edge(g, nodes["group"], nodes["target"], edgeDeniable)
	enginetest.Edge(g, nodes["denied"], nodes["other"], edgeControls)
	enginetest.Edge(g, nodes["other"], nodes["other2"], edgeControls)
	enginetest.Edge(g, nodes["other2"], nodes["target"], edgeControls)
	return g, nodes
}

func TestRoutesLeaveOutRefusedSteps(t *testing.T) {
	g, nodes := denyGraph(t)
	session := connect(t, fixedSource{g, frontend.Ready})
	id := func(name string) string { return idOf(t, session, nodes[name]) }

	var out explainOutput
	args := map[string]any{"from": map[string]any{"id": id("denied")}, "to_filter": "(tag=hvt)", "edge_types": []string{"MCPTestControls", "MCPTestDeniable"}}
	if msg := call(t, session, "explain_routes", args, &out); msg != "" {
		t.Fatal(msg)
	}
	if !out.Reachable || out.Shortest != 3 || len(out.Routes) != 1 || out.RefusedSteps == 0 {
		t.Fatalf("reachable %v, shortest %d, %d routes, %d refused steps; want the route of 3 edges", out.Reachable, out.Shortest, len(out.Routes), out.RefusedSteps)
	}
	var labels []string
	for _, n := range out.Routes[0].Nodes {
		labels = append(labels, n.Label)
	}
	if got := strings.Join(labels, " > "); got != "denied > other > other2 > target" {
		t.Errorf("route %s", got)
	}

	var path pathOutput
	if msg := call(t, session, "get_edge_path_details", map[string]any{"node_ids": []string{id("denied"), id("group"), id("target")}}, &path); msg != "" {
		t.Fatal(msg)
	}
	if !path.Refused || len(path.Steps) != 2 || path.Steps[0].Refused || !path.Steps[1].Refused {
		t.Fatalf("path refused %v, steps %+v", path.Refused, path.Steps)
	}
	step := path.Steps[1]
	if step.ActingAs == nil || step.ActingAs.Label != "denied" || len(step.EdgeTypes) != 1 || !step.EdgeTypes[0].Refused {
		t.Errorf("group > target: acting as %+v, types %+v", step.ActingAs, step.EdgeTypes)
	}

	// From the group, standing for every member, nothing is refused.
	var fromGroup pathOutput
	if msg := call(t, session, "get_edge_path_details", map[string]any{"node_ids": []string{id("group"), id("target")}}, &fromGroup); msg != "" || fromGroup.Refused {
		t.Errorf("path from the group refused: %s", msg)
	}
}
