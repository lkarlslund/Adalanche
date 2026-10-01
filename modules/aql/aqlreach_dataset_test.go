package aql_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/aql"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	_ "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	_ "github.com/lkarlslund/adalanche/modules/integrations/localmachine/analyze"
	_ "github.com/lkarlslund/adalanche/modules/integrations/opengraph/analyze"
)

// TestReachAgainstAcyclicOnDataset runs every predefined ACYCLIC query in
// ACYCLIC and in REACH, and prints aggregate counts and times only, as
// "REACHSTAT" lines. Both modes use the UI's default node limit; REACH also
// runs without one.
func TestReachAgainstAcyclicOnDataset(t *testing.T) {
	path := os.Getenv("ADALANCHE_TEST_DATA")
	if path == "" {
		t.Skip("ADALANCHE_TEST_DATA is not set")
	}
	ao, err := engine.Run(path)
	if err != nil {
		t.Fatal("loading failed")
	}

	resolve := func(q string, nodeLimit int) (*graph.Graph[*engine.Node, engine.EdgeBitmap], time.Duration, error) {
		resolver, err := aql.ParseAQLQuery(q, ao)
		if err != nil {
			return nil, 0, err
		}
		opts := aql.NewResolverOptions()
		opts.NodeLimit = nodeLimit
		start := time.Now()
		result, err := resolver.Resolve(opts)
		return result, time.Since(start), err
	}
	missing := func(from, in *graph.Graph[*engine.Node, engine.EdgeBitmap]) (nodes, edges int) {
		for n := range from.Nodes() {
			if !in.HasNode(n) {
				nodes++
			}
		}
		from.IterateEdges(func(s, d *engine.Node, _ engine.EdgeBitmap, _ int) bool {
			if !in.HasEdge(s, d) {
				edges++
			}
			return true
		})
		return
	}

	const uiLimit = 2000
	for i, qd := range aql.PredefinedQueries {
		mode, rest, found := strings.Cut(qd.Query, " ")
		if !found || mode != "ACYCLIC" || !strings.Contains(rest, "]") {
			continue
		}
		acyclic, acyclicTime, err1 := resolve(qd.Query, uiLimit)
		reach, reachTime, err2 := resolve("REACH "+rest, uiLimit)
		full, fullTime, err3 := resolve("REACH "+rest, 0)
		if err1 != nil || err3 != nil {
			fmt.Printf("REACHSTAT %d %q error acyclic=%v reach_full=%v\n", i, qd.Name, err1 != nil, err3 != nil)
			continue
		}
		reachNodes, reachEdges := -1, -1
		if err2 == nil {
			reachNodes, reachEdges = reach.Order(), reach.Size()
		}
		missNodes, missEdges := missing(acyclic, full)
		fmt.Printf("REACHSTAT %d %q acyclic_limited=%d/%d/%.2fs reach_limited=%d/%d/%.2fs reach_full=%d/%d/%.2fs acyclic_not_in_reach=%d/%d\n",
			i, qd.Name,
			acyclic.Order(), acyclic.Size(), acyclicTime.Seconds(),
			reachNodes, reachEdges, reachTime.Seconds(),
			full.Order(), full.Size(), fullTime.Seconds(),
			missNodes, missEdges)
	}
}
