package frontend

import (
	"fmt"
	"maps"
	"os"

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
}

type CytoGraphData struct {
	SharedName string `json:"shared_name"`
	Name       string `json:"name"`
	SUID       int    `json:"SUID"`
}

type CytoElements []CytoFlatElement

type CytoFlatElement struct {
	Data  MapStringInterface `json:"data"`
	Group string             `json:"group"` // nodes or edges
}

func GenerateCytoscapeJS(ao *engine.IndexedGraph, pg graph.Graph[*engine.Node, engine.EdgeBitmap], alldetails bool) (CytoGraph, error) {
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
		nodeid, found := ao.NodeToIndex(node)
		if !found {
			continue
		}
		newnode := CytoFlatElement{
			Group: "nodes",
			Data: map[string]any{
				"id":    fmt.Sprintf("n%v", nodeid),
				"label": node.Label(),
				"type":  node.OneAttrString(engine.Type),
			},
		}

		node.Attr(engine.Tag).Iterate(func(tag engine.AttributeValue) bool {
			newnode.Data[tag.String()] = true
			return true
		})

		maps.Copy(newnode.Data, df)

		// If we added empty junk, remove it again
		for attr, value := range newnode.Data {
			if value == "" || (attr == "objectSid" && value == "NULL SID") {
				delete(newnode.Data, attr)
			}
		}

		if df["target"] == true {
			newnode.Data["_querytarget"] = true
		}
		if df["source"] == true {
			newnode.Data["_querysource"] = true
		}
		if df["canexpand"] != 0 {
			newnode.Data["_canexpand"] = df["canexpand"]
		}

		g.Elements[i] = newnode

		i++
	}

	pg.IterateEdges(func(source, target *engine.Node, edge engine.EdgeBitmap, flow int) bool {
		sourceid, found1 := ao.NodeToIndex(source)
		targetid, found2 := ao.NodeToIndex(target)
		if !found1 || !found2 {
			return true
		}
		cytoedge := CytoFlatElement{
			Group: "edges",
			Data: MapStringInterface{
				"id":       fmt.Sprintf("e%v-%v", sourceid, targetid),
				"source":   fmt.Sprintf("n%v", sourceid),
				"target":   fmt.Sprintf("n%v", targetid),
				"flow":     flow,
				"_maxprob": edge.MaxProbability(source, target),
				"methods":  edge.StringSlice(),
			},
		}

		g.Elements[i] = cytoedge

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
	data, err := qjson.MarshalIndent(g, "", "  ")
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
