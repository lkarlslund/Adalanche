package aql

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
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
		g.Add(nodes[name])
	}
	for _, e := range edges {
		g.EdgeToEx(nodes[e.from], nodes[e.to], testEdges[e.kind], true)
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
			if got, want := runQuery(t, g(), tt.aql, opts), strings.Join(tt.want, "\n"); got != want {
				t.Fatalf("%s gives\n%s\nwant\n%s", tt.aql, got, want)
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
	g.Add(user)
	g.Add(group)
	g.EdgeToEx(user, group, memberOf, true)

	template := func(name string, published bool, flex ...any) {
		n := engine.NewNode(append([]any{engine.Name, name, engine.Type, engine.NodeTypeCertificateTemplate.ValueString()}, flex...)...)
		if published {
			n.Tag("published")
		}
		g.Add(n)
		g.EdgeToEx(group, n, enroll, true)
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
