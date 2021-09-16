package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
)

func ExportGraphViz(pg PwnGraph, filename string) error {
	df, _ := os.Create(filename)
	defer df.Close()

	fmt.Fprintln(df, "digraph G {")
	for _, node := range pg.Nodes {
		object := node.Object
		var formatting = ""
		switch object.Type() {
		case ObjectTypeComputer:
			formatting = ""
		}
		fmt.Fprintf(df, "    \"%v\" [label=\"%v\";%v];\n", object.GUID(), object.OneAttr(Name), formatting)
	}
	fmt.Fprintln(df, "")
	for _, connection := range pg.Connections {
		fmt.Fprintf(df, "    \"%v\" -> \"%v\" [label=\"%v\"];\n", connection.Source.GUID(), connection.Target.GUID(), connection.GetMethodBitmap().JoinedString())
	}
	fmt.Fprintln(df, "}")

	return nil
}

type MethodMap map[string]bool

type CytoData map[string]interface{}

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
	Group string   `json:"group"` // nodes or edges
	Data  CytoData `json:"data"`
}

func GenerateCytoscapeJS(pg PwnGraph, alldetails bool) (CytoGraph, error) {
	g := CytoGraph{
		FormatVersion:            "1.0",
		GeneratedBy:              programname + " " + commit + " " + builddate,
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
				"id":                       fmt.Sprintf("n%v", object.ID),
				"label":                    object.Label(),
				DistinguishedName.String(): object.DN(),
				Name.String():              object.OneAttr(Name),
				DisplayName.String():       object.OneAttr(DisplayName),
				Description.String():       object.OneAttr(Description),
				ObjectSid.String():         object.SID().String(),
				SAMAccountName.String():    object.OneAttr(SAMAccountName),
			}}

		for attr, values := range object.Attributes {
			if (attr.IsMeta() && !strings.HasPrefix(attr.String(), "_gpofile/")) || alldetails {
				if values.Len() == 1 {
					newnode.Data[attr.String()] = values.Slice()[0].String()
				} else {
					newnode.Data[attr.String()] = values.StringSlice()
				}
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
			Data: CytoData{
				"id":     fmt.Sprintf("e%v-%v", connection.Source.ID, connection.Target.ID),
				"source": fmt.Sprintf("n%v", connection.Source.ID),
				"target": fmt.Sprintf("n%v", connection.Target.ID),
			},
		}
		var maxprob Probability
		for _, method := range connection.Methods() {
			prob := connection.GetProbability(method)
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

func ExportCytoscapeJS(pg PwnGraph, filename string) error {
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
