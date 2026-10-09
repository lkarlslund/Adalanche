package frontend

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/version"
)

func ExportGraphViz(pg graph.Graph[*engine.Node, engine.EdgeBitmap], filename string) error {
	df, _ := os.Create(filename)
	defer df.Close()

	fmt.Fprintln(df, "digraph G {")
	for object := range pg.Nodes() {
		var formatting = ""
		switch object.Type() {
		case engine.NodeTypeComputer:
			formatting = ""
		}
		fmt.Fprintf(df, "    \"%v\" [label=\"%v\";%v];\n", object.ID(), object.OneAttr(activedirectory.Name), formatting)
	}
	fmt.Fprintln(df, "")

	pg.IterateEdges(func(source, target *engine.Node, edge engine.EdgeBitmap, flow int) bool {
		fmt.Fprintf(df, "    \"%v\" -> \"%v\" [label=\"%v\"];\n", source, target, edge.JoinedString())
		return true
	})
	fmt.Fprintln(df, "}")

	return nil
}

type MethodMap map[string]bool

type MapStringInterface map[string]any

type CytoGraph struct {
	FormatVersion            string        `json:"format_version"`
	GeneratedBy              string        `json:"generated_by"`
	TargetCytoscapeJSVersion string        `json:"target_cytoscapejs_version"`
	Data                     CytoGraphData `json:"data"`
	Elements                 CytoElements  `json:"elements"`
	// EdgeCombos holds each distinct set of edge types once when edges
	// refer to it by index ("combo") instead of listing their "methods".
	EdgeCombos [][]string `json:"edge_combos,omitempty"`
}

type CytoGraphData struct {
	SharedName string `json:"shared_name"`
	Name       string `json:"name"`
	SUID       int    `json:"SUID"`
}

type CytoElements []CytoFlatElement

// CytoFlatElement is a node, with MapStringInterface data, or an edge, with
// *CytoEdgeData.
type CytoFlatElement struct {
	Data  any    `json:"data"`
	Group string `json:"group"` // nodes or edges
}

// CytoEdgeData describes an edge. Edges are most of a large result, so they
// are structs rather than maps.
type CytoEdgeData struct {
	ID             string             `json:"id"`
	Source         string             `json:"source"`
	Target         string             `json:"target"`
	Flow           int                `json:"flow"`
	MaxProbability engine.Probability `json:"_maxprob"`
	Methods        []string           `json:"methods,omitempty"`
	Combo          *int               `json:"combo,omitempty"` // index into CytoGraph.EdgeCombos
}

// GenerateCytoscapeJS describes a result graph as Cytoscape elements. With
// sharedCombos, edges name their edge types by an index into EdgeCombos, as
// the graph itself keeps them; a result has few distinct combinations and
// many edges.
func GenerateCytoscapeJS(_ *engine.IndexedGraph, pg graph.Graph[*engine.Node, engine.EdgeBitmap], sharedCombos bool) (CytoGraph, error) {
	g := CytoGraph{
		FormatVersion:            "1.0",
		GeneratedBy:              version.ProgramVersionShort(),
		TargetCytoscapeJSVersion: "~3.0",
		Data: CytoGraphData{
			SharedName: "Adalanche analysis data",
			Name:       "Adalanche analysis data",
		},
	}

	/*
		// Sort the nodes to get consistency
		sort.Slice(pg.Nodes, func(i, j int) bool {
			return pg.Nodes[i].Node.ID() < pg.Nodes[j].Node.ID()
		})

		// Sort the connections to get consistency
		sort.Slice(pg.Connections, func(i, j int) bool {
			return pg.Connections[i].Source.ID() < pg.Connections[j].Source.ID() ||
				(pg.Connections[i].Source.ID() == pg.Connections[j].Source.ID() &&
					pg.Connections[i].Target.ID() < pg.Connections[j].Target.ID())
		})
	*/

	g.Elements = make(CytoElements, pg.Order()+pg.Size())
	var i int
	for node, df := range pg.Nodes() {
		nodeid := node.ID()
		data := MapStringInterface{
			"id":    fmt.Sprintf("n%v", nodeid),
			"label": node.Label(),
			"type":  node.OneAttrString(engine.Type),
		}

		node.Attr(engine.Tag).Iterate(func(tag engine.AttributeValue) bool {
			data[tag.String()] = true
			return true
		})

		maps.Copy(data, df)

		// If we added empty junk, remove it again
		for attr, value := range data {
			if value == "" || (attr == "objectSid" && value == "NULL SID") {
				delete(data, attr)
			}
		}

		if df["target"] == true {
			data["_querytarget"] = true
		}
		if df["source"] == true {
			data["_querysource"] = true
		}
		if df["canexpand"] != 0 {
			data["_canexpand"] = df["canexpand"]
		}

		g.Elements[i] = CytoFlatElement{Group: "nodes", Data: data}

		i++
	}

	// Edge data is allocated in one block; each combination's index once.
	edges := make([]CytoEdgeData, 0, pg.Size())
	combos := map[engine.EdgeBitmap]*int{}
	pg.IterateEdges(func(source, target *engine.Node, edge engine.EdgeBitmap, flow int) bool {
		sourceid := strconv.FormatUint(uint64(source.ID()), 10)
		targetid := strconv.FormatUint(uint64(target.ID()), 10)
		edges = append(edges, CytoEdgeData{
			ID:             "e" + sourceid + "-" + targetid,
			Source:         "n" + sourceid,
			Target:         "n" + targetid,
			Flow:           flow,
			MaxProbability: edge.MaxProbability(source, target),
		})
		data := &edges[len(edges)-1]
		if sharedCombos {
			combo, found := combos[edge]
			if !found {
				combo = new(int)
				*combo = len(g.EdgeCombos)
				combos[edge] = combo
				names := edge.StringSlice()
				slices.Sort(names)
				g.EdgeCombos = append(g.EdgeCombos, names)
			}
			data.Combo = combo
		} else {
			data.Methods = edge.StringSlice()
		}
		g.Elements[i] = CytoFlatElement{Group: "edges", Data: data}
		i++
		return true
	})

	return g, nil
}

func ExportCytoscapeJS(ao *engine.IndexedGraph, pg graph.Graph[*engine.Node, engine.EdgeBitmap], filename string) error {
	g, err := GenerateCytoscapeJS(ao, pg, false)
	if err != nil {
		return err
	}
	data, err := JSON.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}

	df, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer df.Close()
	_, err = df.Write(data)

	return err
}
