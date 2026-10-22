package aql

import (
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
)

var edgeTagSecondEdge = engine.NewEdge("EdgeTagTestSecond")

// The tests here use edge tags, which an extension enables.
func init() { EnableEdgeTags() }

// Without the extension that provides edge tags, edgetag= is refused.
func TestEdgeTagsNeedEnabling(t *testing.T) {
	edgeTagsEnabled.Store(false)
	defer edgeTagsEnabled.Store(true)
	for _, q := range []string{"()-[edgetag=accepted]->()", "()-[!edgetag=accepted]->()"} {
		if _, err := ParseAQLQuery(q, nil); err == nil || !strings.Contains(err.Error(), "Enterprise") {
			t.Errorf("%v: %v, want it refused", q, err)
		}
	}
	if _, err := ParseAQLQuery("()-[!tag=Pivot]->()", nil); err != nil {
		t.Errorf("other negations are not affected: %v", err)
	}
}

func (tg *transitGraph) tagEdge(from, to string, edge engine.Edge, tag string) {
	enginetest.Update(tg.g, func(tx *engine.Tx) { tx.TagEdge(tg.node(from), tg.node(to), edge, tag) })
}

// edgetag= follows only edge types with the tag, !edgetag= only those
// without; a tag on the pair is on every edge type between it.
func TestEdgeTagFilters(t *testing.T) {
	tg := newTransitGraph([]string{"S>A>E", "S>B>E"}, nil)
	tg.tagEdge("S", "A", transitTestEdge, "accepted")
	tg.tagEdge("S", "B", engine.AnyEdgeType, "reviewed")
	tg.tagEdge("B", "E", engine.AnyEdgeType, "reviewed")

	for _, c := range []struct{ step, want, edges string }{
		{"", "A,B,E,S", ""},
		{"!edgetag=accepted", "B,E,S", "B>E,S>B"},
		{"edgetag=reviewed", "B,E,S", "B>E,S>B"},
		{"edgetag=accepted", "", ""}, // A>E is not tagged, so no route ends
		{"edgetag=nosuchtag", "", ""},
		{"!edgetag=nosuchtag", "A,B,E,S", ""},
		{"edgetag=reviewed, !edgetag=accepted", "B,E,S", ""},
	} {
		checkModes(t, tg, c.step, c.want, c.edges)
	}
}

// A tag on one edge type leaves the pair's other types to follow; the
// result keeps only the types the route used.
func TestEdgeTagOnOneType(t *testing.T) {
	tg := newTransitGraph([]string{"S>E"}, nil)
	enginetest.Edge(tg.g, tg.node("S"), tg.node("E"), edgeTagSecondEdge)
	tg.tagEdge("S", "E", transitTestEdge, "accepted")

	resolver, err := ParseAQLQuery("REACH start:(name=S)-[!edgetag=accepted]{1,2}->end:(name=E)", tg.g)
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(NewResolverOptions())
	if err != nil {
		t.Fatal(err)
	}
	eb, found := result.GetEdge(tg.node("S"), tg.node("E"))
	if !found || eb.IsSet(transitTestEdge) || !eb.IsSet(edgeTagSecondEdge) {
		t.Errorf("kept %v, want the untagged type alone", eb.StringSlice())
	}
	// With the tag on the pair instead, nothing is left.
	tg.tagEdge("S", "E", engine.AnyEdgeType, "accepted")
	if nodes, _ := tg.resolve(t, "REACH start:(name=S)-[!edgetag=accepted]{1,2}->end:(name=E)"); len(nodes) != 0 {
		t.Errorf("pair tag: %v, want no route", nodes)
	}
}

// Tags are on edges as stored; a query walking edges backwards still sees
// them on the right edge.
func TestEdgeTagsWalkingBackwards(t *testing.T) {
	tg := newTransitGraph([]string{"A>T", "B>T"}, nil)
	tg.tagEdge("A", "T", transitTestEdge, "accepted")
	for _, mode := range []string{"REACH", "ACYCLIC", "WALK"} {
		nodes, _ := tg.resolve(t, mode+" start:(name=T)<-[!edgetag=accepted]{1,2}-end:(|(name=A)(name=B))")
		if !slices.Equal(nodes, names("B,T")) {
			t.Errorf("%v: %v, want B and T", mode, nodes)
		}
	}
}

// Negations in edge filters parse: !EdgeType, !tag= and !edgetag=.
func TestEdgeFilterNegationsParse(t *testing.T) {
	for _, q := range []string{
		"()-[!TransitTestEdge]->()",
		"()-[TransitTestEdge, !EdgeTagTestSecond]->()",
		"()-[!tag=Pivot]->()",
		"()-[edgetag=accepted]->()",
		"()-[!edgetag=accepted, tag=Pivot]{1,3}->()",
	} {
		if _, err := ParseAQLQuery(q, nil); err != nil {
			t.Errorf("%v: %v", q, err)
		}
	}
	for _, q := range []string{
		"()-[edgetag accepted]->()",
		"()-[edgetag=]->()",
		"()-[!]->()",
	} {
		if _, err := ParseAQLQuery(q, nil); err == nil {
			t.Errorf("%v: no error", q)
		}
	}
}
