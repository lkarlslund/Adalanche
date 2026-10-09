package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/aql"
	"github.com/lkarlslund/adalanche/modules/engine"
)

// TestDatasetSnapshot loads the dataset in ADALANCHE_TEST_DATA and writes a
// snapshot of the analysed graph to ADALANCHE_SNAPSHOT_DIR, so two builds can
// be compared without printing anything from the data. Node identities are
// hashed. The files stay on the machine; only totals are printed.
func TestDatasetSnapshot(t *testing.T) {
	path, out := os.Getenv("ADALANCHE_TEST_DATA"), os.Getenv("ADALANCHE_SNAPSHOT_DIR")
	if path == "" || out == "" {
		t.Skip("ADALANCHE_TEST_DATA and ADALANCHE_SNAPSHOT_DIR are not set")
	}
	knownEdges := len(engine.Edges())
	knownTypes := len(engine.NodeTypes())

	start := time.Now()
	ao, err := engine.Run(path)
	if err != nil {
		t.Fatal("loading failed")
	}
	fmt.Printf("STAT load_seconds %.1f\n", time.Since(start).Seconds())

	create := func(name string) (*bufio.Writer, func()) {
		f, err := os.Create(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		w := bufio.NewWriterSize(f, 1<<20)
		return w, func() {
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			f.Close()
		}
	}

	ids := map[*engine.Node]string{}
	var id func(n *engine.Node) string
	id = func(n *engine.Node) string {
		if h, found := ids[n]; found {
			return h
		}
		var key string
		switch {
		case n.DN() != "":
			key = "dn|" + strings.ToLower(n.DN())
		case !n.SID().IsBlank():
			key = "sid|" + n.SID().String() + "|" + strings.ToLower(n.OneAttrString(engine.DomainContext)) + "|" + n.OneAttrString(engine.DataSource)
		default:
			// Nodes without a DN or SID, such as a machine's services and
			// executables, are told apart by where they are in the tree.
			key = "other|" + n.Type().String() + "|" + strings.ToLower(n.Label()) + "|" + n.OneAttrString(engine.DataSource)
			if parent := n.Parent(); parent != nil {
				key += "|" + id(parent)
			}
		}
		sum := sha256.Sum256([]byte(key))
		h := hex.EncodeToString(sum[:8])
		ids[n] = h
		return h
	}
	typeName := func(n *engine.Node) string {
		if nt := n.Type(); int(nt) <= knownTypes {
			return nt.String()
		}
		return "(named by data)"
	}
	kind := func(n *engine.Node) string {
		switch sid := n.SID(); {
		case n.DN() != "":
			return "dn"
		case sid.IsBlank() && strings.HasPrefix(n.Label(), "OBJ "):
			return "unlabelled" // identity key changes between runs
		case sid.IsBlank():
			return "other"
		case sid.Component(2) == 21 && sid.Component(3) != 0:
			return "account-sid"
		default:
			return "well-known-sid"
		}
	}
	edgeName := func(e engine.Edge) string {
		if int(e) < knownEdges {
			return e.String()
		}
		return "(named by data)"
	}

	nodes, closeNodes := create("nodes.tsv")
	edges, closeEdges := create("edges.tsv")
	tags, closeTags := create("tags.tsv")
	var nodeCount, edgeCount int
	ao.Iterate(func(n *engine.Node) bool {
		nodeCount++
		fmt.Fprintf(nodes, "%s\t%s\t%s\n", id(n), typeName(n), kind(n))
		for _, tag := range n.Attr(engine.Tag).StringSlice() {
			fmt.Fprintf(tags, "%s\t%s\n", id(n), tag)
		}
		ao.IterateEdges(n, engine.Out, func(target *engine.Node, eb engine.EdgeBitmap) bool {
			for _, e := range eb.Edges() {
				edgeCount++
				fmt.Fprintf(edges, "%s\t%s\t%s\n", id(n), id(target), edgeName(e))
			}
			return true
		})
		return true
	})
	closeNodes()
	closeEdges()
	closeTags()
	fmt.Printf("STAT nodes_total %d\n", nodeCount)
	fmt.Printf("STAT edges_total %d\n", edgeCount)

	// Every predefined query with the UI's default node limit, and the
	// ACYCLIC ones again in REACH mode, whose result does not depend on
	// node order (numbered from 1000).
	type namedQuery struct {
		index int
		text  string
	}
	var all []namedQuery
	for i, qd := range aql.PredefinedQueries {
		all = append(all, namedQuery{i, qd.Query})
		if mode, rest, found := strings.Cut(qd.Query, " "); found && mode == "ACYCLIC" {
			all = append(all, namedQuery{1000 + i, "REACH " + rest})
		}
	}
	queries, closeQueries := create("queries.tsv")
	for _, q := range all {
		i := q.index
		resolver, err := aql.ParseAQLQuery(q.text, ao)
		if err != nil {
			fmt.Fprintf(queries, "%d\terror\tparse\n", i)
			continue
		}
		opts := aql.NewResolverOptions()
		opts.NodeLimit = 2000
		qstart := time.Now()
		result, err := resolver.Resolve(opts)
		if err != nil {
			fmt.Fprintf(queries, "%d\terror\tresolve\n", i)
			continue
		}
		fmt.Fprintf(queries, "%d\ttime\t%.3f\n", i, time.Since(qstart).Seconds())
		for n := range result.Nodes() {
			fmt.Fprintf(queries, "%d\tnode\t%s\n", i, id(n))
		}
		result.IterateEdges(func(s, d *engine.Node, _ engine.EdgeBitmap, _ int) bool {
			fmt.Fprintf(queries, "%d\tedge\t%s\t%s\n", i, id(s), id(d))
			return true
		})
	}
	closeQueries()
}
