package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

// Two forests: A with its root and a second tree, B with only a root. The
// data holds A's configuration only, as when one forest was collected.
func multiForestGraph(t *testing.T) *engine.IndexedGraph {
	t.Helper()
	const rootA, treeA, rootB = "DC=a,DC=test", "DC=tree,DC=test", "DC=b,DC=test"
	crossRef := func(name, forestRoot, nc string) *engine.Node {
		return engine.NewNode(engine.DistinguishedName, "CN="+name+",CN=Partitions,CN=Configuration,"+forestRoot,
			engine.ObjectClass, "crossRef", NCName, nc)
	}
	return newADTestGraph(
		crossRef("A", rootA, rootA), crossRef("TREE", rootA, treeA), crossRef("B", rootB, rootB),
		engine.NewNode(engine.Name, "Directory Service",
			engine.DistinguishedName, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+rootA,
			activedirectory.DsHeuristics, "0000000001000001"),
		engine.NewNode(engine.Name, "First-Site", engine.ObjectClass, "site",
			engine.DistinguishedName, "CN=First-Site,CN=Sites,CN=Configuration,"+rootA),
	)
}

func TestInForest(t *testing.T) {
	graph := multiForestGraph(t)
	for _, tt := range []struct {
		domain, root string
		want         bool
	}{
		{"DC=a,DC=test", "dc=a,dc=test", true},
		{"DC=tree,DC=test", "DC=a,DC=test", true},       // second tree, by its crossRef
		{"DC=b,DC=test", "DC=a,DC=test", false},         // another forest
		{"DC=child,DC=a,DC=test", "DC=a,DC=test", true}, // no crossRef: by name
		{"DC=other,DC=test", "DC=a,DC=test", false},
		{"", "DC=a,DC=test", false},
	} {
		if got := engine.InForest(graph, tt.domain, tt.root); got != tt.want {
			t.Errorf("InForest(%q, %q) = %v, want %v", tt.domain, tt.root, got, tt.want)
		}
	}
}

// Forest settings and sites reach every domain of their forest, including a
// second tree, and no domain of another forest.
func TestForestSettingsStayInTheirForest(t *testing.T) {
	graph := multiForestGraph(t)
	for _, tt := range []struct {
		domain     string
		heuristics string
		sites      int
	}{
		{"DC=a,DC=test", "0000000001000001", 1},
		{"DC=tree,DC=test", "0000000001000001", 1},
		{"DC=b,DC=test", "", 0},
	} {
		if got := forestHeuristics(graph, tt.domain); got != tt.heuristics {
			t.Errorf("%s: dSHeuristics %q, want %q", tt.domain, got, tt.heuristics)
		}
		if got := len(forestSites(graph, tt.domain)); got != tt.sites {
			t.Errorf("%s: %d sites, want %d", tt.domain, got, tt.sites)
		}
	}
}
