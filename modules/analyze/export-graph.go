package analyze

import (
	"bytes"
	"fmt"
	"os"
	"sort"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/version"
)

func ExportGraphViz(pg engine.PwnGraph, filename string) error {
	df, _ := os.Create(filename)
	defer df.Close()

	fmt.Fprintln(df, "digraph G {")
	for _, node := range pg.Nodes {
		object := node.Object
		var formatting = ""
		switch object.Type() {
		case engine.ObjectTypeComputer:
			formatting = ""
		}
		fmt.Fprintf(df, "    \"%v\" [label=\"%v\";%v];\n", object.GUID(), object.OneAttr(activedirectory.Name), formatting)
	}
	fmt.Fprintln(df, "")
	for _, connection := range pg.Connections {
		fmt.Fprintf(df, "    \"%v\" -> \"%v\" [label=\"%v\"];\n", connection.Source.GUID(), connection.Target.GUID(), connection.JoinedString())
	}
	fmt.Fprintln(df, "}")

	return nil
}

type MethodMap map[string]bool

type MapStringInterface map[string]interface{}

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
	Group string             `json:"group"` // nodes or edges
	Data  MapStringInterface `json:"data"`
}

func GenerateCytoscapeJS(pg engine.PwnGraph, alldetails bool) (CytoGraph, error) {
	g := CytoGraph{
		FormatVersion:            "1.0",
		GeneratedBy:              version.ProgramVersionShort(),
		TargetCytoscapeJSVersion: "~3.0",
		Data: CytoGraphData{
			SharedName: "adalanche analysis data",
			Name:       "adalanche analysis data",
		},
	}

	// Sort the nodes to get consistency
	sort.Slice(pg.Nodes, func(i, j int) bool {
		return bytes.Compare(pg.Nodes[i].Object.GUID().Bytes(), pg.Nodes[j].Object.GUID().Bytes()) == -1
	})

	// Sort the connections to get consistency
	sort.Slice(pg.Connections, func(i, j int) bool {
		return bytes.Compare(
			pg.Connections[i].Source.GUID().Bytes(),
			pg.Connections[i].Source.GUID().Bytes()) == -1 ||
			bytes.Compare(pg.Connections[i].Target.GUID().Bytes(),
				pg.Connections[i].Target.GUID().Bytes()) == -1
	})

	g.Elements = make(CytoElements, len(pg.Nodes)+len(pg.Connections))
	var i int
	for _, node := range pg.Nodes {
		object := node.Object

		newnode := CytoFlatElement{
			Group: "nodes",
			Data: map[string]interface{}{
				"id":    fmt.Sprintf("n%v", object.ID()),
				"label": object.Label(),
				"type":  object.Type().String(),
			},
		}

		for key, value := range node.DynamicFields {
			newnode.Data[key] = value
		}

		// FIXME, should go elsewhere
		if uac, ok := object.AttrInt(activedirectory.UserAccountControl); ok && uac&engine.UAC_ACCOUNTDISABLE != 0 {
			newnode.Data["_disabled"] = true
		}

		// If we added empty junk, remove it again
		for attr, value := range newnode.Data {
			if value == "" || (attr == "objectSid" && value == "NULL SID") {
				delete(newnode.Data, attr)
			}
		}

		if node.Target {
			newnode.Data["_querytarget"] = true
		}
		if node.CanExpand != 0 {
			newnode.Data["_canexpand"] = node.CanExpand
		}

		g.Elements[i] = newnode

		i++
	}

	for _, connection := range pg.Connections {
		edge := CytoFlatElement{
			Group: "edges",
			Data: MapStringInterface{
				"id":     fmt.Sprintf("e%v-%v", connection.Source.ID(), connection.Target.ID()),
				"source": fmt.Sprintf("n%v", connection.Source.ID()),
				"target": fmt.Sprintf("n%v", connection.Target.ID()),
			},
		}

		for key, value := range connection.DynamicFields {
			edge.Data[key] = value
		}

		var maxprob engine.Probability
		for _, method := range connection.Methods() {
			prob := method.Probability(connection.Source, connection.Target)
			edge.Data["method_"+method.String()] = prob
			if prob > maxprob {
				maxprob = prob
			}
		}
		edge.Data["_maxprob"] = maxprob

		g.Elements[i] = edge

		i++
	}

	return g, nil
}

func ExportCytoscapeJS(pg engine.PwnGraph, filename string) error {
	g, err := GenerateCytoscapeJS(pg, false)
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
	df.Write(data)

	return nil
}
