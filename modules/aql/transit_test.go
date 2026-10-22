package aql

import (
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
)

var (
	transitTestEdge  = engine.NewEdge("TransitTestEdge")
	transitTestReset = engine.NewEdge("TransitTestReset").RegisterProbabilityCalculator(
		func(_, _ *engine.Node, _ *engine.EdgeBitmap) engine.Probability { return 10 })
)

// transitGraph is a small graph of named nodes for transit constraint tests.
type transitGraph struct {
	g     *engine.IndexedGraph
	nodes map[string]*engine.Node
}

// newTransitGraph builds a graph from routes written "a>b>c" (an edge per
// hop) and tags given as name -> tags.
func newTransitGraph(routes []string, tags map[string][]string) *transitGraph {
	tg := &transitGraph{g: engine.NewIndexedGraph(), nodes: map[string]*engine.Node{}}
	for _, route := range routes {
		hops := strings.Split(route, ">")
		for i := 1; i < len(hops); i++ {
			enginetest.Edge(tg.g, tg.node(hops[i-1]), tg.node(hops[i]), transitTestEdge)
		}
	}
	for name, ts := range tags {
		for _, tag := range ts {
			enginetest.Tag(tg.g, tg.node(name), tag)
		}
	}
	return tg
}

func (tg *transitGraph) node(name string) *engine.Node {
	if n, found := tg.nodes[name]; found {
		return n
	}
	n := enginetest.AddNew(tg.g, engine.Name, name)
	tg.nodes[name] = n
	return n
}

// resolve runs q and returns the names of the result's nodes and its edges
// ("a>b"), sorted.
func (tg *transitGraph) resolve(t *testing.T, q string) (nodes, edges []string) {
	t.Helper()
	resolver, err := ParseAQLQuery(q, tg.g)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	result, err := resolver.Resolve(NewResolverOptions())
	if err != nil {
		t.Fatalf("resolve %q: %v", q, err)
	}
	for n := range result.Nodes() {
		nodes = append(nodes, n.Label())
	}
	result.IterateEdges(func(from, to *engine.Node, _ engine.EdgeBitmap, _ int) bool {
		edges = append(edges, from.Label()+">"+to.Label())
		return true
	})
	slices.Sort(nodes)
	slices.Sort(edges)
	return nodes, edges
}

func names(s string) []string {
	if s == "" {
		return nil
	}
	n := strings.Split(s, ",")
	slices.Sort(n)
	return n
}

func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// checkModes runs one edge step from S to E in every mode. REACH must give
// exactly want (nodes, and edges when wantEdges is set); WALK, which lists
// every route and counts along each, must agree with it exactly, as the
// fixtures have no cycles. ACYCLIC and TRAIL skip nodes or edges already in
// the result, so they must only reach E when REACH does and stay inside it.
func checkModes(t *testing.T, tg *transitGraph, step, want, wantEdges string) {
	t.Helper()
	q := "start:(name=S)-[" + step + "]{1,6}->end:(name=E)"
	reachNodes, reachEdges := tg.resolve(t, "REACH "+q)
	if !slices.Equal(reachNodes, names(want)) {
		t.Errorf("REACH [%v]: nodes %v, want %v", step, reachNodes, names(want))
	}
	if wantEdges != "" && !slices.Equal(reachEdges, names(wantEdges)) {
		t.Errorf("REACH [%v]: edges %v, want %v", step, reachEdges, names(wantEdges))
	}
	walkNodes, walkEdges := tg.resolve(t, "WALK "+q)
	if !slices.Equal(walkNodes, reachNodes) || !slices.Equal(walkEdges, reachEdges) {
		t.Errorf("WALK [%v]: %v %v, REACH gave %v %v", step, walkNodes, walkEdges, reachNodes, reachEdges)
	}
	reaches := slices.Contains(reachNodes, "E")
	for _, mode := range []string{"ACYCLIC", "TRAIL"} {
		nodes, edges := tg.resolve(t, mode+" "+q)
		if slices.Contains(nodes, "E") != reaches || !subset(nodes, reachNodes) || !subset(edges, reachEdges) {
			t.Errorf("%v [%v]: %v %v, REACH gave %v %v", mode, step, nodes, edges, reachNodes, reachEdges)
		}
	}
}

// A node that matches an exclusion can not be passed through: with the
// constraint there is no route, without it there is. All the ways to say
// it agree, including the bare filter (the old path node requirement).
func TestTransitExcludesSingleHop(t *testing.T) {
	tg := newTransitGraph([]string{"S>X>E"}, map[string][]string{"X": {"bad"}})
	checkModes(t, tg, "", "E,S,X", "S>X,X>E")
	for _, step := range []string{
		"avoid (tag=bad)",
		"via 0 (tag=bad)",
		"(!(tag=bad))",
		"through (!(tag=bad))",
		"via all (!(tag=bad))",
	} {
		checkModes(t, tg, step, "", "")
	}
}

// Every hop is checked, not just the first: an excluded node deep in the
// route drops that route entirely, edges and all, while a parallel clean
// route stays.
func TestTransitExcludesMidPath(t *testing.T) {
	tg := newTransitGraph([]string{"S>Y>X>Z>E"}, map[string][]string{"X": {"bad"}})
	checkModes(t, tg, "", "E,S,X,Y,Z", "")
	checkModes(t, tg, "avoid (tag=bad)", "", "")

	tg = newTransitGraph([]string{"S>Y>X>Z>E", "Y>W>Z"}, map[string][]string{"X": {"bad"}})
	checkModes(t, tg, "avoid (tag=bad)", "E,S,W,Y,Z", "S>Y,W>Z,Y>W,Z>E")
}

// The start and end node are not transit nodes, so constraints never apply
// to them: they may be named as start or end even when they could not be
// passed through.
func TestTransitExemptsStartAndEnd(t *testing.T) {
	tg := newTransitGraph([]string{"S>E", "S>M>E"}, map[string][]string{
		"S": {"bad"}, "E": {"bad"}, "M": {"ok"},
	})
	checkModes(t, tg, "avoid (tag=bad)", "E,M,S", "S>E,S>M,M>E")
	checkModes(t, tg, "through (tag=ok)", "E,M,S", "S>E,S>M,M>E")
	checkModes(t, tg, "via all (tag=ok)", "E,M,S", "")
	// Only the direct route has no transit node at all.
	checkModes(t, tg, "avoid (tag=ok)", "E,S", "S>E")
}

// Counting transit nodes. Routes from S to E, with their transit groups:
//
//	S>u1>E      0 groups, 1 other
//	S>g1>E      1 group
//	S>g2>g3>E   2 groups
//	S>g4>u2>E   1 group, 1 other
//	S>u3>u4>E   0 groups, 2 others
func TestTransitCounts(t *testing.T) {
	tg := newTransitGraph(
		[]string{"S>u1>E", "S>g1>E", "S>g2>g3>E", "S>g4>u2>E", "S>u3>u4>E"},
		map[string][]string{"g1": {"group"}, "g2": {"group"}, "g3": {"group"}, "g4": {"group"}},
	)
	for _, c := range []struct{ step, want string }{
		{"via 0 (tag=group)", "E,S,u1,u3,u4"},
		{"via 1 (tag=group)", "E,S,g1,g4,u2"},
		{"via =1 (tag=group)", "E,S,g1,g4,u2"},
		{"via 2 (tag=group)", "E,S,g2,g3"},
		{"via 3 (tag=group)", ""},
		{"via >=1 (tag=group)", "E,S,g1,g2,g3,g4,u2"},
		{"via >1 (tag=group)", "E,S,g2,g3"},
		{"via <=1 (tag=group)", "E,S,g1,g4,u1,u2,u3,u4"},
		{"via <2 (tag=group)", "E,S,g1,g4,u1,u2,u3,u4"},
		{"via <1 (tag=group)", "E,S,u1,u3,u4"},
		{"via all (tag=group)", "E,S,g1,g2,g3"},
		{"through (tag=group)", "E,S,g1,g2,g3"},
		{"via all but 0 (tag=group)", "E,S,g1,g2,g3"},
		{"via all but 1 (tag=group)", "E,S,g1,g2,g3,g4,u1,u2"},
		{"via all but 2 (tag=group)", "E,S,g1,g2,g3,g4,u1,u2,u3,u4"},
		// Constraints combine: at least one group, but never g1.
		{"via >=1 (tag=group), avoid (name=g1)", "E,S,g2,g3,g4,u2"},
		// And sit beside edge types.
		{"TransitTestEdge, via 1 (tag=group)", "E,S,g1,g4,u2"},
	} {
		checkModes(t, tg, c.step, c.want, "")
	}
}

// A count belongs to the whole route, so an edge is only kept when some
// route through it has the right count. Here b is reached both with and
// without a group before it; only the route through g has one, so a and
// the edge a>b are not on any valid route, though b and b>E are.
func TestTransitCountIsPerRoute(t *testing.T) {
	tg := newTransitGraph([]string{"S>a>b>E", "S>g>b>E"}, map[string][]string{"g": {"group"}})
	checkModes(t, tg, "via 1 (tag=group)", "E,S,b,g", "S>g,b>E,g>b")
	checkModes(t, tg, "via 0 (tag=group)", "E,S,a,b", "S>a,a>b,b>E")
}

// Counts are of hops through matching nodes. REACH lets a route revisit a
// node, so a loop through a group counts it again; ACYCLIC never revisits.
func TestTransitCountsHops(t *testing.T) {
	tg := newTransitGraph([]string{"S>g>h>E", "h>g"}, map[string][]string{"g": {"group"}})
	q := "start:(name=S)-[via 2 (tag=group)]{1,6}->end:(name=E)"
	nodes, edges := tg.resolve(t, "REACH "+q)
	if !slices.Equal(nodes, names("E,S,g,h")) || !slices.Contains(edges, "h>g") {
		t.Errorf("REACH: %v %v, want the loop through g twice", nodes, edges)
	}
	if nodes, _ := tg.resolve(t, "ACYCLIC "+q); len(nodes) != 0 {
		t.Errorf("ACYCLIC: %v, want no route (g can only be passed once)", nodes)
	}
	nodes, _ = tg.resolve(t, "REACH start:(name=S)-[via 1 (tag=group)]{1,6}->end:(name=E)")
	if !slices.Equal(nodes, names("E,S,g,h")) {
		t.Errorf("REACH via 1: %v", nodes)
	}
}

// Each step keeps its own count, starting again at zero where the step
// before it lands, and the landing node (M here, itself a group) is not a
// transit node of either step.
func TestTransitCountsPerStep(t *testing.T) {
	tg := newTransitGraph(
		[]string{"S>g1>M>g2>E", "M>u>E"},
		map[string][]string{"g1": {"group"}, "g2": {"group"}, "M": {"group"}},
	)
	for _, c := range []struct{ second, want string }{
		{"avoid (tag=group)", "E,M,S,g1,u"},
		// Had the count carried over from the first step, the second would
		// start at one and g2 would make it two.
		{"via 1 (tag=group)", "E,M,S,g1,g2"},
	} {
		q := "start:(name=S)-[via 1 (tag=group)]{1,4}->(name=M)-[" + c.second + "]{1,4}->end:(name=E)"
		for _, mode := range []string{"REACH", "WALK", "ACYCLIC", "TRAIL"} {
			if nodes, _ := tg.resolve(t, mode+" "+q); !slices.Equal(nodes, names(c.want)) {
				t.Errorf("%v [%v]: %v, want %v", mode, c.second, nodes, names(c.want))
			}
		}
	}
}

// A step that may take no edges only lands with no edges when its counts
// allow zero transit nodes.
func TestTransitZeroEdgeStep(t *testing.T) {
	tg := newTransitGraph([]string{"S>g>E"}, map[string][]string{"g": {"group"}})
	for _, mode := range []string{"REACH", "ACYCLIC"} {
		if nodes, _ := tg.resolve(t, mode+" start:(name=S)-[via 0 (tag=group)]{0,2}->end:(name=S)"); !slices.Equal(nodes, names("S")) {
			t.Errorf("%v via 0: %v, want S on its own", mode, nodes)
		}
		if nodes, _ := tg.resolve(t, mode+" start:(name=S)-[via >=1 (tag=group)]{0,2}->end:(name=S)"); len(nodes) != 0 {
			t.Errorf("%v via >=1: %v, want nothing", mode, nodes)
		}
	}
}

// An out= or in= subquery counts any edge of the type unless it says how
// probable the edge must be. The exclusion below is a negation, so matching
// a low-probability edge excludes more nodes and hides routes.
func TestTransitEdgeSubqueryProbability(t *testing.T) {
	tg := newTransitGraph([]string{"S>P>E"}, nil)
	// P can reset DC's password, but only with probability 10.
	enginetest.Edge(tg.g, tg.node("P"), tg.node("DC"), transitTestReset)

	for _, c := range []struct {
		step string
		want string
	}{
		{"", "E,P,S"},
		{"avoid (out=TransitTestReset,(name=DC))", ""},
		{"(!(out=TransitTestReset,(name=DC)))", ""},
		{"avoid (out=TransitTestReset>=10,(name=DC))", ""},
		{"avoid (out=TransitTestReset>=100,(name=DC))", "E,P,S"},
		{"avoid (out=TransitTestReset>50)", "E,P,S"},
		{"avoid (in=TransitTestReset,(name=P))", "E,P,S"}, // DC is not on the route
	} {
		checkModes(t, tg, c.step, c.want, "")
	}
	// The subquery is resolved once over the whole graph, not the route:
	// it is the same set of nodes either way.
	resolver, err := ParseAQLQuery("(out=TransitTestReset,(name=DC))", tg.g)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(NewResolverOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasNode(tg.node("P")) || result.Order() != 1 {
		t.Errorf("subquery matched %v nodes, want P alone", result.Order())
	}
}

// REACH refuses a search whose via counts would make it track too many
// states, rather than allocating them.
func TestTransitReachStateLimit(t *testing.T) {
	if err := reachStatesFit(9, 1_000_000, 3); err != nil {
		t.Errorf("a via count on a million nodes was refused: %v", err)
	}
	if err := reachStatesFit(9, 1_000_000, 4096); err == nil {
		t.Error("4096 count values on a million nodes was allowed")
	}
}

func TestTransitParsing(t *testing.T) {
	tg := newTransitGraph([]string{"S>g>E"}, map[string][]string{"g": {"group"}})
	route := func(q string) ReachRoutes {
		t.Helper()
		resolver, err := ParseAQLQuery(q, tg.g)
		if err != nil {
			t.Fatalf("parse %q: %v", q, err)
		}
		return resolver.(AQLquery).Routes
	}
	// The default REACH keeps the cheapest route when the query allows
	// recombining; gates allow it, counts do not.
	if r := route("start:(name=S)-[avoid (tag=group)]{1,4}->end:(name=E)"); r != RoutesCheapest {
		t.Errorf("gate: routes %v, want cheapest", r)
	}
	if r := route("start:(name=S)-[via 1 (tag=group)]{1,4}->end:(name=E)"); r != RoutesAll {
		t.Errorf("count: routes %v, want all", r)
	}
	// So the default works for either, and CHEAPEST with a gate too.
	for _, q := range []string{
		"start:(name=S)-[via 1 (tag=group)]{1,4}->end:(name=E)",
		"start:(name=S)-[through (tag=group)]{1,4}->end:(name=E)",
		"REACH CHEAPEST start:(name=S)-[avoid (name=x)]{1,4}->end:(name=E)",
		"REACH SHORTEST start:(name=S)-[via all (tag=group)]{1,4}->end:(name=E)",
	} {
		if nodes, _ := tg.resolve(t, q); !slices.Equal(nodes, names("E,S,g")) {
			t.Errorf("%v: %v", q, nodes)
		}
	}

	resolveErr := func(q string) error {
		resolver, err := ParseAQLQuery(q, tg.g)
		if err != nil {
			return err
		}
		_, err = resolver.Resolve(NewResolverOptions())
		return err
	}
	for _, q := range []string{
		"REACH CHEAPEST start:(name=S)-[via 1 (tag=group)]{1,4}->end:(name=E)", // counts can not be recombined
		"start:(name=S)-[via (tag=group)]{1,4}->end:(name=E)",                  // a count is required
		"start:(name=S)-[via all but (tag=group)]{1,4}->end:(name=E)",          // and after "but"
		"start:(name=S)-[via 1]{1,4}->end:(name=E)",                            // and a filter
		"start:(name=S)-[avoid]{1,4}->end:(name=E)",
		"start:(name=S)-[via 100 (tag=group), via 100 (name=x)]{1,4}->end:(name=E)", // too many count states
	} {
		if resolveErr(q) == nil {
			t.Errorf("%v: no error", q)
		}
	}
}
