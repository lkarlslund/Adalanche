package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	edgeControls = engine.NewEdge("MCPTestControls")
	testCause    = engine.NewSourceKind("MCP test cause")
	// An attribute only an import would create, named like a secret.
	importedSecret = engine.NewAttribute("ms-Mcs-AdmPwd")
	badPwdCount    = engine.NewAttribute("badPwdCount")
)

type fixedSource struct {
	g      *engine.IndexedGraph
	status frontend.WebServiceStatus
}

func (f fixedSource) Status() frontend.WebServiceStatus { return f.status }
func (f fixedSource) Graph() *engine.IndexedGraph       { return f.g }
func (f fixedSource) Docs() DocsFS                      { return nil }

// testGraph: users u1..u5 control a group, the group controls an admin
// account, which controls the target tagged hvt. The group's edge to the
// admin has a recorded cause. The admin holds secrets.
func testGraph(t *testing.T) (*engine.IndexedGraph, map[string]*engine.Node) {
	t.Helper()
	g := engine.NewIndexedGraph()
	nodes := map[string]*engine.Node{}
	for _, name := range []string{"u1", "u2", "u3", "u4", "u5", "group", "admin", "target"} {
		nodes[name] = engine.NewNode(engine.Name, name)
		enginetest.Add(g, nodes[name])
	}
	enginetest.Set(g, nodes["admin"], engine.LookupAttribute("unicodePwd"), engine.NV("hash"))
	enginetest.Set(g, nodes["admin"], importedSecret, engine.NV("local admin password"))
	enginetest.Set(g, nodes["admin"], badPwdCount, engine.NV("3"))
	enginetest.Tag(g, nodes["target"], "hvt")
	for _, u := range []string{"u1", "u2", "u3", "u4", "u5"} {
		enginetest.Edge(g, nodes[u], nodes["group"], edgeControls)
	}
	enginetest.Update(g, func(tx *engine.Tx) {
		tx.EdgeBecause(nodes["group"], nodes["admin"], edgeControls, engine.Source{Kind: testCause, About: nodes["target"], Detail: "granted here"})
	})
	enginetest.Edge(g, nodes["admin"], nodes["target"], edgeControls)
	return g, nodes
}

func connect(t *testing.T, source graphSource) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := newServer(source)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.mcp.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

// call runs a tool and decodes its result into out, or returns the error
// text the tool gave.
func call(t *testing.T, session *mcp.ClientSession, tool string, args map[string]any, out any) string {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	if result.IsError {
		var text []string
		for _, c := range result.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text = append(text, tc.Text)
			}
		}
		return strings.Join(text, " ")
	}
	body, _ := json.Marshal(result.StructuredContent)
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return ""
}

// idOf gives a node's id as tools do, tagged with the current load.
func idOf(t *testing.T, session *mcp.ClientSession, node *engine.Node) string {
	t.Helper()
	var status statusOutput
	if msg := call(t, session, "get_status", nil, &status); msg != "" || status.Meta.Load == "" {
		t.Fatalf("no load tag: %s", msg)
	}
	return strconv.FormatUint(uint64(node.ID()), 10) + "@" + status.Meta.Load
}

func TestSecretsStayInside(t *testing.T) {
	g, nodes := testGraph(t)
	session := connect(t, fixedSource{g, frontend.Ready})
	admin := map[string]any{"id": idOf(t, session, nodes["admin"])}

	var details nodeDetailsOutput
	if msg := call(t, session, "get_node_details", admin, &details); msg != "" {
		t.Fatal(msg)
	}
	for _, name := range []string{"unicodePwd", "ms-Mcs-AdmPwd"} {
		if got := details.Node.Attributes[name]; !slices.Equal(got, []string{redacted}) {
			t.Errorf("%s returned as %q", name, got)
		}
	}
	if got := details.Node.Attributes["badPwdCount"]; !slices.Equal(got, []string{"3"}) {
		t.Errorf("badPwdCount, a fact about passwords, returned as %q", got)
	}

	for _, args := range []map[string]any{
		{"filter": "(unicodePwd=hash)"},
		{"filter": "(&(name=admin)(ms-Mcs-AdmPwd=local*))"},
		{"filter": "(*=hash)"},
		{"filter": "(name=*)", "order_by": "unicodePwd"},
	} {
		var out findNodesOutput
		if msg := call(t, session, "find_nodes", args, &out); msg == "" {
			t.Errorf("find_nodes %v answered: %d nodes", args, out.Total)
		}
	}
	var out runOutput
	if msg := call(t, session, "run_aql", map[string]any{"query": "REACH start:(unicodePwd=hash)<-[]{1,2}-end:()"}, &out); msg == "" {
		t.Error("run_aql filtered on a secret")
	}
}

func TestExplainRoutesWithCauses(t *testing.T) {
	g, nodes := testGraph(t)
	session := connect(t, fixedSource{g, frontend.Ready})
	var out explainOutput
	if msg := call(t, session, "explain_routes", map[string]any{"from": map[string]any{"id": idOf(t, session, nodes["u1"])}, "to_filter": "(tag=hvt)"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if !out.Reachable || out.Shortest != 3 || len(out.Routes) != 1 {
		t.Fatalf("reachable %v, shortest %d, %d routes; want a route of 3 edges", out.Reachable, out.Shortest, len(out.Routes))
	}
	var labels []string
	for _, n := range out.Routes[0].Nodes {
		labels = append(labels, n.Label)
	}
	if got := strings.Join(labels, " > "); got != "u1 > group > admin > target" {
		t.Errorf("route %s", got)
	}
	causes := out.Routes[0].Steps[1].EdgeTypes[0].Causes
	if len(causes) != 1 || causes[0].Kind != "MCP test cause" || causes[0].Detail != "granted here" || causes[0].About == nil || causes[0].About.Label != "target" {
		t.Errorf("causes of group > admin: %+v", causes)
	}

	if msg := call(t, session, "explain_routes", map[string]any{"from": map[string]any{"id": idOf(t, session, nodes["target"])}, "to": map[string]any{"id": idOf(t, session, nodes["u1"])}}, &out); msg != "" || out.Reachable {
		t.Errorf("routes run against edge direction: %v %s", out.Reachable, msg)
	}
}

func TestReachSummaryAndNeighbors(t *testing.T) {
	g, nodes := testGraph(t)
	session := connect(t, fixedSource{g, frontend.Ready})
	var reach reachOutput
	if msg := call(t, session, "reach_summary", map[string]any{"id": idOf(t, session, nodes["target"]), "direction": "in"}, &reach); msg != "" {
		t.Fatal(msg)
	}
	var counts []int
	for _, hop := range reach.Hops {
		counts = append(counts, hop.Count)
	}
	if !slices.Equal(counts, []int{1, 1, 5}) || reach.Total != 7 {
		t.Errorf("hops %v, total %d; want [1 1 5] and 7", counts, reach.Total)
	}

	var neighbors neighborsOutput
	if msg := call(t, session, "get_neighbors", map[string]any{"id": idOf(t, session, nodes["group"]), "direction": "in", "limit": 2}, &neighbors); msg != "" {
		t.Fatal(msg)
	}
	if neighbors.Total != 5 || len(neighbors.Edges) != 2 || !neighbors.Truncated || neighbors.Edges[0].Neighbor.Label != "u1" {
		t.Errorf("neighbors: total %d, %d returned, truncated %v", neighbors.Total, len(neighbors.Edges), neighbors.Truncated)
	}
}

func TestRunAQLMergesAndCountsHops(t *testing.T) {
	g, _ := testGraph(t)
	session := connect(t, fixedSource{g, frontend.Ready})
	var out runOutput
	if msg := call(t, session, "run_aql", map[string]any{"query": "REACH start:(tag=hvt)<-[]{1,4}-end:(name=u*)"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.DrawnNodes != 4 || out.TotalNodes != 8 || out.NodesPerHop["3"] != 5 {
		t.Fatalf("%d drawn, %d nodes, per hop %v; want the five users drawn as one at hop 3 and counted as five",
			out.DrawnNodes, out.TotalNodes, out.NodesPerHop)
	}
	last := out.Nodes[len(out.Nodes)-1]
	if last.Merged != 5 || len(last.Members) != 5 || last.Role != "end" || last.Hop == nil || *last.Hop != 3 {
		t.Errorf("merged users: %+v", last)
	}
	if first := out.Nodes[0]; first.Label != "target" || first.Role != "start" {
		t.Errorf("first node %+v, want the target", first)
	}

	if msg := call(t, session, "run_aql", map[string]any{"query": "ACYCLIC start:(tag=hvt)<-[]{1,4}-end:(name=u*)", "merge": "off", "node_limit": 3}, &out); msg != "" {
		t.Fatal(msg)
	}
	if len(out.Incomplete) == 0 {
		t.Error("a result cut by the node limit does not say so")
	}
}

func TestNotReady(t *testing.T) {
	g, _ := testGraph(t)
	session := connect(t, fixedSource{g, frontend.Loading})
	var status statusOutput
	if msg := call(t, session, "get_status", nil, &status); msg != "" || status.Meta.Ready {
		t.Errorf("status while loading: %+v %s", status, msg)
	}
	var out findNodesOutput
	if msg := call(t, session, "find_nodes", map[string]any{"filter": "(name=u1)"}, &out); !strings.Contains(msg, "loading") {
		t.Errorf("find_nodes while loading: %q", msg)
	}
}

// Browsers on other sites cannot call the endpoint.
func TestCrossOriginRefused(t *testing.T) {
	g, _ := testGraph(t)
	handler := newServer(fixedSource{g, frontend.Ready}).handler()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/mcp", strings.NewReader(`{}`))
	request.Header.Set("Origin", "https://elsewhere.example")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("cross-site request got %d", recorder.Code)
	}
}

// Node ids hold for one load of the graph: ids without the tag, or with
// another load's, are refused, and keys name nodes across loads.
func TestNodeIDsAndKeys(t *testing.T) {
	g, nodes := testGraph(t)
	enginetest.Set(g, nodes["admin"], engine.ObjectSid, engine.NV(windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")))
	session := connect(t, fixedSource{g, frontend.Ready})
	id := idOf(t, session, nodes["admin"])
	number, _, _ := strings.Cut(id, "@")

	var details nodeDetailsOutput
	for _, args := range []map[string]any{
		{"id": number},
		{"id": number + "@ffffff"},
	} {
		if msg := call(t, session, "get_node_details", args, &details); msg == "" {
			t.Errorf("node id %v was taken", args["id"])
		}
	}
	if msg := call(t, session, "get_node_details", map[string]any{"id": id}, &details); msg != "" || details.Node.Label != "admin" {
		t.Fatalf("current id: %s", msg)
	}
	if details.Node.Key != "objectSid=S-1-5-21-1-2-3-1001" {
		t.Fatalf("key %q", details.Node.Key)
	}
	var byKey nodeDetailsOutput
	if msg := call(t, session, "get_node_details", map[string]any{"id": details.Node.Key}, &byKey); msg != "" || byKey.Node.NodeID != id {
		t.Errorf("by key: %s %+v", msg, byKey.Node.NodeBrief)
	}
}
