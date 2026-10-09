package aql

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/graph"
)

var (
	edgeHop    = engine.NewEdge("AQLTestHop")
	edgeOther  = engine.NewEdge("AQLTestOther")
	edgeWeak   = engine.NewEdge("AQLTestWeak").RegisterProbabilityCalculator(func(_, _ *engine.Node, _ *engine.EdgeBitmap) engine.Probability { return 30 })
	testEdges  = map[string]engine.Edge{"hop": edgeHop, "other": edgeOther, "weak": edgeWeak}
	edgeLabels = map[engine.Edge]string{edgeHop: "hop", edgeOther: "other", edgeWeak: "weak"}
)

// testGraph builds a graph from "from -kind-> to" lines. Nodes and edges are
// added in an order shuffled by seed, so tests can check that results do not
// depend on how the graph was built. Seed 0 keeps the written order.
func testGraph(t *testing.T, seed uint64, lines ...string) *engine.IndexedGraph {
	t.Helper()
	type edge struct{ from, kind, to string }
	var edges []edge
	var names []string
	seen := map[string]bool{}
	for _, line := range lines {
		var e edge
		if _, err := fmt.Sscanf(line, "%s -%s %s", &e.from, &e.kind, &e.to); err != nil {
			t.Fatalf("bad edge %q: %v", line, err)
		}
		e.kind = strings.TrimSuffix(e.kind, "->")
		if _, ok := testEdges[e.kind]; !ok {
			t.Fatalf("unknown edge kind %q", e.kind)
		}
		edges = append(edges, e)
		for _, n := range []string{e.from, e.to} {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	if seed != 0 {
		r := rand.New(rand.NewPCG(seed, seed))
		r.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
		r.Shuffle(len(edges), func(i, j int) { edges[i], edges[j] = edges[j], edges[i] })
	}
	g := engine.NewIndexedGraph()
	nodes := map[string]*engine.Node{}
	for _, name := range names {
		nodes[name] = engine.NewNode(engine.Name, name)
		enginetest.Add(g, nodes[name])
	}
	for _, e := range edges {
		enginetest.Edge(g, nodes[e.from], nodes[e.to], testEdges[e.kind])
	}
	return g
}

// render describes a result graph as sorted text: one line per edge with its
// kinds and flow, then nodes without edges.
func render(result *graph.Graph[*engine.Node, engine.EdgeBitmap]) string {
	var lines []string
	linked := map[*engine.Node]bool{}
	result.IterateEdges(func(s, t *engine.Node, eb engine.EdgeBitmap, flow int) bool {
		var kinds []string
		for _, e := range eb.Edges() {
			kinds = append(kinds, edgeLabels[e])
		}
		slices.Sort(kinds)
		lines = append(lines, fmt.Sprintf("%s -%s-> %s flow=%d", s.Label(), strings.Join(kinds, ","), t.Label(), flow))
		linked[s], linked[t] = true, true
		return true
	})
	for n := range result.Nodes() {
		if !linked[n] {
			lines = append(lines, n.Label())
		}
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

func runQuery(t *testing.T, g *engine.IndexedGraph, aql string, opts ResolverOptions) string {
	t.Helper()
	resolver, err := ParseAQLQuery(aql, g)
	if err != nil {
		t.Fatalf("%s: %v", aql, err)
	}
	result, err := resolver.Resolve(opts)
	if err != nil {
		t.Fatalf("%s: %v", aql, err)
	}
	return render(result)
}

// A graph where several paths of equal length compete for the same nodes,
// so in ACYCLIC mode the answer depends on which path is found first.
var competingPaths = []string{
	"s1 -hop-> m1", "s1 -hop-> m2", "s1 -hop-> m3", "s1 -hop-> m4",
	"s2 -hop-> m2", "s2 -hop-> m3", "s2 -hop-> m5",
	"m1 -hop-> m2", "m2 -hop-> m3", "m3 -hop-> m4", "m4 -hop-> m5", "m5 -hop-> m1",
	"m1 -hop-> x1", "m2 -hop-> x1", "m3 -hop-> x2", "m4 -hop-> x2", "m5 -hop-> x1",
	"x1 -hop-> end", "x2 -hop-> end", "m3 -hop-> end",
}

func TestAQLResultsDoNotDependOnGraphBuildOrder(t *testing.T) {
	queries := []struct {
		aql  string
		opts ResolverOptions
	}{
		{"ACYCLIC start:(name=s*)-[AQLTestHop]{1,4}->end:(name=end)", NewResolverOptions()},
		{"ACYCLIC start:(name=s*)-[AQLTestHop]{1,3}->mid:(name=m*)-[AQLTestHop]{1,2}->end:(name=end)", NewResolverOptions()},
		{"TRAIL start:(name=s*)-[AQLTestHop]{1,4}->end:(name=end)", NewResolverOptions()},
		{"ACYCLIC start:(name=s*)-[AQLTestHop]{1,4}->end:(name=end)", func() ResolverOptions { o := NewResolverOptions(); o.NodeLimit = 5; return o }()},
		{"REACH start:(name=s*)-[AQLTestHop]{1,4}->end:(name=end)", NewResolverOptions()},
		{"REACH start:(name=s*)-[AQLTestHop]{1,3}->mid:(name=m*)-[AQLTestHop]{1,2}->end:(name=end)", NewResolverOptions()},
		{"REACH start:(name=s*)-[AQLTestHop]{1,4}->end:(name=end)", func() ResolverOptions { o := NewResolverOptions(); o.NodeLimit = 8; return o }()},
	}
	for _, q := range queries {
		want := runQuery(t, testGraph(t, 0, competingPaths...), q.aql, q.opts)
		if want == "" {
			t.Fatalf("%s: empty result", q.aql)
		}
		for seed := uint64(1); seed <= 25; seed++ {
			if got := runQuery(t, testGraph(t, seed, competingPaths...), q.aql, q.opts); got != want {
				t.Fatalf("%s (node limit %d): build order %d gives\n%s\nwant\n%s", q.aql, q.opts.NodeLimit, seed, got, want)
			}
		}
	}
}

func TestAQLResults(t *testing.T) {
	g := func() *engine.IndexedGraph {
		return testGraph(t, 0,
			"a -hop-> b", "b -hop-> c", "c -hop-> d",
			"a -other-> c",
			"a -weak-> e", "e -hop-> d",
			"f -hop-> a",
		)
	}
	for _, tt := range []struct {
		name, aql string
		opts      func(*ResolverOptions)
		want      []string
	}{
		{
			name: "only the named edge kind is followed",
			aql:  "start:(name=a)-[AQLTestHop]{1,3}->end:(name=d)",
			want: []string{"a -hop-> b flow=1", "b -hop-> c flow=1", "c -hop-> d flow=1"},
		},
		{
			name: "any edge kind",
			aql:  "start:(name=a)-[]{1,2}->end:(name=d)",
			want: []string{"a -other-> c flow=1", "a -weak-> e flow=1", "c -hop-> d flow=1", "e -hop-> d flow=1"},
		},
		{
			name: "exact depth",
			aql:  "start:(name=a)-[AQLTestHop]{2}->end:()",
			want: []string{"a -hop-> b flow=1", "b -hop-> c flow=1"},
		},
		{
			name: "incoming direction",
			aql:  "start:(name=c)<-[AQLTestHop]{1,3}-end:(name=f)",
			want: []string{"a -hop-> b flow=1", "b -hop-> c flow=1", "f -hop-> a flow=1"},
		},
		{
			name: "edge probability filter",
			aql:  "start:(name=a)-[AQLTestWeak,AQLTestHop,probability>=50]{1,2}->end:(name=d)",
			want: nil,
		},
		{
			name: "minimum edge probability option",
			aql:  "start:(name=a)-[AQLTestWeak,AQLTestHop]{1,2}->end:(name=d)",
			opts: func(o *ResolverOptions) { o.MinEdgeProbability = 50 },
			want: nil,
		},
		{
			name: "path node requirement",
			aql:  "start:(name=a)-[AQLTestHop,AQLTestWeak,(name=e)]{1,3}->end:(name=d)",
			want: []string{"a -weak-> e flow=1", "e -hop-> d flow=1"},
		},
		{
			name: "two steps",
			aql:  "start:(name=f)-[AQLTestHop]->mid:(name=a)-[AQLTestOther]->end:(name=c)",
			want: []string{"a -other-> c flow=1", "f -hop-> a flow=1"},
		},
		{
			name: "union",
			aql:  "start:(name=a)-[AQLTestOther]->end:(name=c) UNION start:(name=e)-[AQLTestHop]->end:(name=d)",
			want: []string{"a -other-> c flow=1", "e -hop-> d flow=1"},
		},
		{
			name: "max depth option",
			aql:  "start:(name=f)-[AQLTestHop]{1,5}->end:(name=d)",
			opts: func(o *ResolverOptions) { o.MaxDepth = 3 },
			want: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := NewResolverOptions()
			if tt.opts != nil {
				tt.opts(&opts)
			}
			// No route here has a choice of paths, so every mode agrees.
			for _, mode := range []string{"", "REACH "} {
				aql := mode + tt.aql
				if got, want := runQuery(t, g(), aql, opts), strings.Join(tt.want, "\n"); got != want {
					t.Fatalf("%s gives\n%s\nwant\n%s", aql, got, want)
				}
			}
		})
	}
}

func TestAQLModesReuseAcrossTheResult(t *testing.T) {
	// The short path s->m->e is found first. The longer s->a->m->e reuses
	// the edge m->e and the nodes m and e from it.
	g := func() *engine.IndexedGraph {
		return testGraph(t, 0, "s -hop-> m", "m -hop-> e", "s -hop-> a", "a -hop-> m")
	}
	shortOnly := []string{"m -hop-> e flow=1", "s -hop-> m flow=1"}
	for _, tt := range []struct {
		mode string
		want []string
	}{
		{"WALK", []string{"a -hop-> m flow=1", "m -hop-> e flow=2", "s -hop-> a flow=1", "s -hop-> m flow=1"}},
		{"TRAIL", shortOnly},
		{"ACYCLIC", shortOnly},
		{"REACH", []string{"a -hop-> m flow=1", "m -hop-> e flow=2", "s -hop-> a flow=1", "s -hop-> m flow=1"}},
	} {
		aql := tt.mode + " start:(name=s)-[AQLTestHop]{1,3}->end:(name=e)"
		if got, want := runQuery(t, g(), aql, NewResolverOptions()), strings.Join(tt.want, "\n"); got != want {
			t.Errorf("%s gives\n%s\nwant\n%s", aql, got, want)
		}
	}
	if _, err := ParseAQLQuery("SIMPLE (name=s)-[]->(name=e)", nil); err == nil {
		t.Error("SIMPLE is no longer a query mode")
	}
}

func TestESC1QueryMatchesOnlyIssuableTemplates(t *testing.T) {
	var esc1 string
	for _, q := range PredefinedQueries {
		if strings.HasPrefix(q.Name, "Enroll in ESC1 ") {
			esc1 = q.Query
		}
	}
	if esc1 == "" {
		t.Fatal("ESC1 query not found")
	}
	enroll := engine.NewEdge("CertificateEnroll")
	memberOf := engine.NewEdge("MemberOf")
	nameFlag := engine.NewAttribute("msPKI-Certificate-Name-Flag")
	enrollmentFlag := engine.NewAttribute("msPKI-Enrollment-Flag")
	raSignature := engine.NewAttribute("msPKI-RA-Signature")
	eku := engine.NewAttribute("pKIExtendedKeyUsage")

	g := engine.NewIndexedGraph()
	user := engine.NewNode(engine.Name, "user", engine.Type, engine.NodeTypeUser.ValueString())
	group := engine.NewNode(engine.Name, "enrollers", engine.Type, engine.NodeTypeGroup.ValueString())
	enginetest.Add(g, user)
	enginetest.Add(g, group)
	enginetest.Edge(g, user, group, memberOf)

	template := func(name string, published bool, flex ...any) {
		n := engine.NewNode(append([]any{engine.Name, name, engine.Type, engine.NodeTypeCertificateTemplate.ValueString()}, flex...)...)
		enginetest.Add(g, n)
		if published {
			enginetest.Tag(g, n, "published")
		}
		enginetest.Edge(g, group, n, enroll)
	}
	clientAuth := "1.3.6.1.5.5.7.3.2"
	template("client auth", true, nameFlag, int64(1), eku, clientAuth)
	template("pkinit", true, nameFlag, int64(1), eku, "1.3.6.1.5.2.3.4")
	template("no usage limits", true, nameFlag, int64(1))
	template("signature count zero", true, nameFlag, int64(1), eku, clientAuth, raSignature, int64(0))
	template("not published", false, nameFlag, int64(1), eku, clientAuth)
	template("manager approval", true, nameFlag, int64(1), eku, clientAuth, enrollmentFlag, int64(2))
	template("signature required", true, nameFlag, int64(1), eku, clientAuth, raSignature, int64(1))
	template("subject from directory", true, nameFlag, int64(0), eku, clientAuth)
	template("server auth only", true, nameFlag, int64(1), eku, "1.3.6.1.5.5.7.3.1")

	resolver, err := ParseAQLQuery(esc1, g)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(NewResolverOptions())
	if err != nil {
		t.Fatal(err)
	}
	var matched []string
	for n := range result.Nodes() {
		if n.Type() == engine.NodeTypeCertificateTemplate {
			matched = append(matched, n.Label())
		}
	}
	slices.Sort(matched)
	want := []string{"client auth", "no usage limits", "pkinit", "signature count zero"}
	if !slices.Equal(matched, want) {
		t.Fatalf("ESC1 matched %v, want %v", matched, want)
	}
}

func TestAQLNegation(t *testing.T) {
	g := testGraph(t, 0, "a -hop-> b", "b -hop-> c")
	for _, tt := range []struct{ aql, want string }{
		{"(!(name=a))", "b\nc"},
		{"(!name=a)", "b\nc"},
		{"(&(!(name=a))(!(name=c)))", "b"},
		{"(!(|(name=a)(name=b)))", "c"},
		{"(!(!(name=a)))", "a"},
	} {
		if got := runQuery(t, g, tt.aql, NewResolverOptions()); got != tt.want {
			t.Errorf("%s gives %q, want %q", tt.aql, got, tt.want)
		}
	}
}

func TestAQLReach(t *testing.T) {
	for _, tt := range []struct {
		name  string
		graph []string
		aql   string
		opts  func(*ResolverOptions)
		want  []string
	}{
		{
			name:  "routes may revisit a node",
			graph: []string{"s -hop-> a", "a -hop-> b", "b -hop-> a", "a -hop-> e"},
			aql:   "REACH start:(name=s)-[AQLTestHop]{1,4}->end:(name=e)",
			want:  []string{"a -hop-> b flow=1", "a -hop-> e flow=2", "b -hop-> a flow=1", "s -hop-> a flow=2"},
		},
		{
			name:  "a loop too long for the step is left out",
			graph: []string{"s -hop-> a", "a -hop-> b", "b -hop-> a", "a -hop-> e"},
			aql:   "REACH start:(name=s)-[AQLTestHop]{1,3}->end:(name=e)",
			want:  []string{"a -hop-> e flow=1", "s -hop-> a flow=1"},
		},
		{
			name:  "edges off every route are left out",
			graph: []string{"s -hop-> a", "a -hop-> e", "a -hop-> x", "x -hop-> y"},
			aql:   "REACH start:(name=s)-[AQLTestHop]{1,5}->end:(name=e)",
			want:  []string{"a -hop-> e flow=1", "s -hop-> a flow=1"},
		},
		{
			name:  "a step of zero edges must land on the next node filter",
			graph: []string{"u -hop-> x"},
			aql:   "REACH start:(name=u)-[AQLTestOther]{0,1}->end:(name=x)",
			want:  nil,
		},
		{
			name:  "a step of zero edges",
			graph: []string{"a -hop-> b", "b -hop-> c"},
			aql:   "REACH start:(name=a)-[AQLTestHop]{0}->mid:(name=a)-[AQLTestHop]->end:()",
			want:  []string{"a -hop-> b flow=1"},
		},
		{
			name:  "a route of zero edges",
			graph: []string{"a -hop-> b"},
			aql:   "REACH start:(name=a)-[AQLTestOther]{0,2}->end:(name=a)",
			want:  []string{"a"},
		},
		{
			name:  "depth limit spans all steps",
			graph: []string{"a -hop-> b", "b -hop-> c", "c -other-> d", "d -other-> e"},
			aql:   "REACH start:(name=a)-[AQLTestHop]{1,2}->mid:()-[AQLTestOther]{1,2}->end:(name=e)",
			opts:  func(o *ResolverOptions) { o.MaxDepth = 3 },
			want:  nil,
		},
		{
			name:  "the same node pair in two steps keeps both steps' edges",
			graph: []string{"a -hop-> b", "a -other-> b", "b -hop-> a"},
			aql:   "REACH start:(name=a)-[AQLTestHop]->mid:(name=b)-[AQLTestHop]->mid2:(name=a)-[AQLTestOther]->end:(name=b)",
			want:  []string{"a -hop,other-> b flow=1", "b -hop-> a flow=1"},
		},
		{
			name:  "over the node limit only the shortest routes are kept",
			graph: []string{"s -hop-> a", "a -hop-> e", "s -hop-> b", "b -hop-> c", "c -hop-> e"},
			aql:   "REACH start:(name=s)-[AQLTestHop]{1,4}->end:(name=e)",
			opts:  func(o *ResolverOptions) { o.NodeLimit = 4 },
			want:  []string{"a -hop-> e flow=1", "s -hop-> a flow=1"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := NewResolverOptions()
			if tt.opts != nil {
				tt.opts(&opts)
			}
			if got, want := runQuery(t, testGraph(t, 0, tt.graph...), tt.aql, opts), strings.Join(tt.want, "\n"); got != want {
				t.Fatalf("%s gives\n%s\nwant\n%s", tt.aql, got, want)
			}
		})
	}
}

func TestAQLReachNodeLimitTooSmall(t *testing.T) {
	g := testGraph(t, 0, "s -hop-> a", "a -hop-> e")
	resolver, err := ParseAQLQuery("REACH start:(name=s)-[AQLTestHop]{1,2}->end:(name=e)", g)
	if err != nil {
		t.Fatal(err)
	}
	opts := NewResolverOptions()
	opts.NodeLimit = 2
	if _, err := resolver.Resolve(opts); err == nil {
		t.Fatal("expected an error when the shortest routes exceed the node limit")
	}
}

func TestAQLReachReferences(t *testing.T) {
	g := testGraph(t, 0, "a -hop-> b", "b -other-> c", "c -hop-> a")
	resolver, err := ParseAQLQuery("REACH start:(name=a)-[AQLTestHop]->mid:(name=b)-[AQLTestOther]->(name=c)", g)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(NewResolverOptions())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for n := range result.Nodes() {
		got[n.Label()] = result.GetNodeData(n, "reference")
	}
	want := map[string]any{"a": "start", "b": "mid", "c": nil}
	for label, ref := range want {
		if got[label] != ref {
			t.Errorf("node %s has reference %v, want %v", label, got[label], ref)
		}
	}
}

// A result cut short by the node limit says so; a complete one says nothing.
func TestAQLResultsReportNodeLimit(t *testing.T) {
	// The smallest limit under each mode's complete answer; REACH needs
	// room for its shortest routes.
	for mode, cut := range map[string]int{"WALK": 3, "TRAIL": 3, "ACYCLIC": 3, "REACH": 4} {
		for _, tt := range []struct {
			limit   int
			limited bool
		}{{0, false}, {100, false}, {cut, true}} {
			g := testGraph(t, 0, competingPaths...)
			aql := mode + " start:(name=s*)-[AQLTestHop]{1,4}->end:(name=end)"
			resolver, err := ParseAQLQuery(aql, g)
			if err != nil {
				t.Fatalf("%s: %v", aql, err)
			}
			opts := NewResolverOptions()
			opts.NodeLimit = tt.limit
			result, err := resolver.Resolve(opts)
			if err != nil {
				t.Fatalf("%s: %v", aql, err)
			}
			if limited := len(result.Limits()) > 0; limited != tt.limited {
				t.Errorf("%s with node limit %d: limited %v (%q), want %v", aql, tt.limit, limited, result.Limits(), tt.limited)
			}
		}
	}
}

// Users that reach the target the same way merge; one with another route,
// and nodes with another role in the query, do not.
func TestMergeIdenticalNodes(t *testing.T) {
	g := testGraph(t, 0,
		"u1 -hop-> grp", "u2 -hop-> grp", "u3 -hop-> grp", "u4 -hop-> grp",
		"u5 -hop-> grp", "u5 -hop-> side", "side -hop-> end",
		"grp -hop-> end", "grp -hop-> uend", "end -hop-> uend")
	for _, mode := range []string{"ACYCLIC", "REACH"} {
		resolver, err := ParseAQLQuery(mode+" start:(name=u*)-[AQLTestHop]{1,3}->end:(name=*end)", g)
		if err != nil {
			t.Fatal(err)
		}
		opts := NewResolverOptions()
		plain, err := resolver.Resolve(opts)
		if err != nil {
			t.Fatal(err)
		}
		wantFlow := 0
		plain.IterateEdges(func(s, d *engine.Node, _ engine.EdgeBitmap, flow int) bool {
			if s.Label() != "u5" && strings.HasPrefix(s.Label(), "u") && d.Label() == "grp" {
				wantFlow += flow
			}
			return true
		})
		opts.MergeNodes = MergeIdentical
		result, err := resolver.Resolve(opts)
		if err != nil {
			t.Fatal(err)
		}
		var merged []string
		for node, data := range result.Nodes() {
			if count, _ := data["_merged"].(int); count > 1 {
				var names []string
				for _, m := range data["_members"].([]MergedMember) {
					names = append(names, m.Label)
				}
				merged = append(merged, fmt.Sprintf("%s=%v", node.Label(), names))
			}
		}
		if want := "[u1=[u1 u2 u3 u4]]"; fmt.Sprint(merged) != want {
			t.Errorf("%s: merged %v, want %s", mode, merged, want)
		}
		var into int
		result.IterateEdges(func(s, d *engine.Node, _ engine.EdgeBitmap, flow int) bool {
			if s.Label() == "u1" && d.Label() == "grp" {
				into = flow
			}
			return true
		})
		if into != wantFlow || into == 0 {
			t.Errorf("%s: merged edge flow %d, want the members' %d", mode, into, wantFlow)
		}
	}
}

// REACH counts merged nodes against the node limit, so the limit reaches
// further when many nodes merge.
func TestAQLReachNodeLimitCountsMergedNodes(t *testing.T) {
	lines := []string{"grp -hop-> mid", "mid -hop-> end"}
	for i := range 20 {
		lines = append(lines, fmt.Sprintf("u%02d -hop-> grp", i))
	}
	g := testGraph(t, 0, lines...)
	resolver, err := ParseAQLQuery("REACH start:(name=u*)-[AQLTestHop]{1,3}->end:(name=end)", g)
	if err != nil {
		t.Fatal(err)
	}
	opts := NewResolverOptions()
	opts.NodeLimit = 5
	if _, err := resolver.Resolve(opts); err == nil {
		t.Fatal("without merging, 23 nodes should not fit a limit of 5")
	}
	opts.MergeNodes = MergeIdentical
	result, err := resolver.Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Order() != 4 || len(result.Limits()) != 0 {
		t.Fatalf("merged: %d nodes, limits %q; want 4 nodes and no limit", result.Order(), result.Limits())
	}
}

// In routes mode, users controlled by different groups merge when they lead
// on to the target the same way, and so do their controllers; identical mode
// keeps them apart. The side compared follows the query's direction.
func TestMergeRoutes(t *testing.T) {
	g := testGraph(t, 0, "c1 -hop-> u1", "c2 -hop-> u2", "c1 -hop-> u3", "u1 -hop-> grp", "u2 -hop-> grp", "u3 -hop-> grp", "grp -hop-> end")
	for _, tt := range []struct {
		aql  string
		mode MergeMode
		want int
	}{
		{"REACH start:(name=end)<-[AQLTestHop]{1,3}-last:(name=c*)", MergeIdentical, 6},
		{"REACH start:(name=end)<-[AQLTestHop]{1,3}-last:(name=c*)", MergeRoutes, 4},
		{"ACYCLIC start:(name=end)<-[AQLTestHop]{1,3}-last:(name=c*)", MergeRoutes, 4},
		// Start nodes never merge by route, so nothing after them does.
		{"REACH start:(name=c*)-[AQLTestHop]{1,3}->last:(name=end)", MergeRoutes, 6},
		{"REACH start:(name=c*)-[AQLTestHop]{1,3}->last:(name=end)", MergeOff, 7},
		// Away from the start, nodes reached the same way merge.
		{"REACH start:(name=c1)-[AQLTestHop]{1,3}->last:(name=end)", MergeRoutes, 4},
	} {
		resolver, err := ParseAQLQuery(tt.aql, g)
		if err != nil {
			t.Fatal(err)
		}
		opts := NewResolverOptions()
		opts.MergeNodes = tt.mode
		result, err := resolver.Resolve(opts)
		if err != nil {
			t.Fatal(err)
		}
		if result.Order() != tt.want {
			t.Errorf("%s merging %q: %d nodes, want %d\n%s", tt.aql, tt.mode, result.Order(), tt.want, render(result))
		}
	}
}

// Nodes record their hop distance from the start nodes; in routes mode a
// machine's local group is drawn as part of the machine, in identical mode
// it is not.
func TestHopsAndMachineFolding(t *testing.T) {
	g := engine.NewIndexedGraph()
	hvt := engine.NewNode(engine.Name, "hvt")
	machine := engine.NewNode(engine.Name, "m1", engine.Type, engine.NodeTypeMachine.ValueString())
	local := engine.NewNode(engine.Name, "localadmins")
	user := engine.NewNode(engine.Name, "u1")
	enginetest.Add(g, hvt, machine, local, user)
	enginetest.ChildOf(g, local, machine)
	enginetest.Edge(g, user, local, edgeHop)
	enginetest.Edge(g, local, machine, edgeHop)
	enginetest.Edge(g, machine, hvt, edgeHop)

	resolver, err := ParseAQLQuery("REACH start:(name=hvt)<-[AQLTestHop]{1,4}-last:(name=u*)", g)
	if err != nil {
		t.Fatal(err)
	}
	opts := NewResolverOptions()
	opts.MergeNodes = MergeIdentical
	result, err := resolver.Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	hops := map[string]any{}
	for node, data := range result.Nodes() {
		hops[node.Label()] = data["_hop"]
	}
	if got := fmt.Sprint(hops); got != "map[hvt:0 localadmins:2 m1:1 u1:3]" {
		t.Errorf("hops %s", got)
	}

	opts.MergeNodes = MergeRoutes
	result, err = resolver.Resolve(opts)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := render(result), "m1 -hop-> hvt flow=1\nu1 -hop-> m1 flow=1"; got != want {
		t.Errorf("folded:\n%s\nwant\n%s", got, want)
	}
	folded, _ := result.GetNodeData(machine, "_folded").([]MergedMember)
	if len(folded) != 1 || folded[0].Label != "localadmins" {
		t.Errorf("machine holds %v, want localadmins", folded)
	}
}

// A search whose caller has given up stops with the context's error.
func TestResolveStopsWhenCancelled(t *testing.T) {
	g := testGraph(t, 0, competingPaths...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, mode := range []string{"WALK", "TRAIL", "ACYCLIC", "REACH"} {
		aql := mode + " start:(name=s*)-[AQLTestHop]{1,4}->end:(name=end)"
		resolver, err := ParseAQLQuery(aql, g)
		if err != nil {
			t.Fatal(err)
		}
		opts := NewResolverOptions()
		opts.Context = ctx
		if _, err := resolver.Resolve(opts); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: error %v, want context.Canceled", aql, err)
		}
	}
}

func TestAQLReachRoutes(t *testing.T) {
	// s1 reaches e1 through a and through b, b less likely; e2 directly but
	// unlikely, and through c in two edges. s2 reaches e1 through a.
	graph := []string{
		"s1 -hop-> a", "a -hop-> e1", "s1 -weak-> b", "b -hop-> e1",
		"s1 -weak-> e2", "s1 -hop-> c", "c -hop-> e2",
		"s2 -hop-> a",
	}
	for _, tt := range []struct {
		aql  string
		want []string
	}{
		{
			// Fewest edges first, then the most likely.
			aql:  "REACH CHEAPEST start:(name=s*)-[AQLTestHop,AQLTestWeak]{1,3}->end:(name=e*)",
			want: []string{"a -hop-> e1 flow=2", "s1 -hop-> a flow=1", "s1 -weak-> e2 flow=1", "s2 -hop-> a flow=1"},
		},
		{
			// From the one start, against the edges.
			aql:  "REACH CHEAPEST start:(name=e1)<-[AQLTestHop,AQLTestWeak]{1,3}-end:(name=s*)",
			want: []string{"a -hop-> e1 flow=2", "s1 -hop-> a flow=1", "s2 -hop-> a flow=1"},
		},
		{
			// Every shortest route; flow counts routes over what is kept.
			aql:  "REACH SHORTEST start:(name=s*)-[AQLTestHop,AQLTestWeak]{1,3}->end:(name=e*)",
			want: []string{"a -hop-> e1 flow=2", "b -hop-> e1 flow=1", "s1 -hop-> a flow=1", "s1 -weak-> b flow=1", "s1 -weak-> e2 flow=1", "s2 -hop-> a flow=1"},
		},
		{
			aql:  "REACH start:(name=s*)-[AQLTestHop,AQLTestWeak]{1,3}->end:(name=e*)",
			want: []string{"a -hop-> e1 flow=2", "b -hop-> e1 flow=1", "c -hop-> e2 flow=1", "s1 -hop-> a flow=1", "s1 -hop-> c flow=1", "s1 -weak-> b flow=1", "s1 -weak-> e2 flow=1", "s2 -hop-> a flow=1"},
		},
	} {
		for _, seed := range []uint64{0, 1, 2} {
			if got, want := runQuery(t, testGraph(t, seed, graph...), tt.aql, NewResolverOptions()), strings.Join(tt.want, "\n"); got != want {
				t.Errorf("%s (seed %d) gives\n%s\nwant\n%s", tt.aql, seed, got, want)
			}
		}
	}

	g := testGraph(t, 0, graph...)
	for _, aql := range []string{
		"ACYCLIC CHEAPEST start:(name=s*)-[AQLTestHop]{1,3}->end:(name=e*)",
		"REACH CHEAPEST SHORTEST start:(name=s*)-[AQLTestHop]{1,3}->end:(name=e*)",
	} {
		if _, err := ParseAQLQuery(aql, g); err == nil {
			t.Errorf("%s parsed", aql)
		}
	}
	resolver, err := ParseAQLQuery("REACH CHEAPEST start:(name=s*)-[AQLTestHop]->mid:()-[AQLTestHop]->end:(name=e*)", g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(NewResolverOptions()); err == nil {
		t.Error("CHEAPEST over two steps resolved")
	}
}

// x is both a start and an end, so s -> x and x -> e are each a route; a
// route from s through x to e is not, as x does not match the path node
// filter. Recombining the edges must not count it.
func TestAQLReachRecombinesOnlyThroughPassableNodes(t *testing.T) {
	g := testGraph(t, 0, "s -hop-> x", "x -hop-> e")
	want := "s -hop-> x flow=1\nx -hop-> e flow=1"
	for _, mode := range []string{"REACH", "REACH SHORTEST", "REACH CHEAPEST"} {
		aql := mode + " start:(|(name=s)(name=x))-[AQLTestHop,(name=m*)]{1,3}->end:(|(name=x)(name=e))"
		if got := runQuery(t, g, aql, NewResolverOptions()); got != want {
			t.Errorf("%s gives\n%s\nwant\n%s", aql, got, want)
		}
	}
}
