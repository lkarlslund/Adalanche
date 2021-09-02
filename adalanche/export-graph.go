package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
)

func ExportGraphViz(pg PwnGraph, filename string) error {
	df, _ := os.Create(filename)
	defer df.Close()

	fmt.Fprintln(df, "digraph G {")
	for _, object := range pg.Implicated {
		var formatting = ""
		switch object.Type() {
		case ObjectTypeComputer:
			formatting = ""
		}
		fmt.Fprintf(df, "    \"%v\" [label=\"%v\";%v];\n", object.GUID(), object.OneAttr(Name), formatting)
	}
	fmt.Fprintln(df, "")
	for _, connection := range pg.Connections {
		fmt.Fprintf(df, "    \"%v\" -> \"%v\" [label=\"%v\"];\n", connection.Source.GUID(), connection.Target.GUID(), connection.Methods.JoinedString())
	}
	fmt.Fprintln(df, "}")

	return nil
}

/*
type CytoID string

type NodeData struct {
	Id                CytoID            `json:"id"`
	Label             string            `json:"label"`
	DistinguishedName string            `json:"distinguishedname,omitempty"`
	Name              string            `json:"name,omitempty"`
	DisplayName       string            `json:"displayname,omitempty"`
	Description       string            `json:"description,omitempty"`
	SID               string            `json:"sid,omitempty"`
	Target            bool              `json:"target,omitempty"`
	SAMaccountname    string            `json:"samaccountname,omitempty"`
	Meta              map[string]string `json:"-,inline"`
}
*/
type CytoNode struct {
	Data map[string]interface{} `json:"data"`
	// Classes []string               `json:"classes"`
}

type MethodMap map[string]bool

type EdgeData map[string]interface{}

type CytoEdge struct {
	Data EdgeData `json:"data"`
	// Classes []string `json:"classes"`
}

type CytoData struct {
	SharedName string `json:"shared_name"`
	Name       string `json:"name"`
	SUID       int    `json:"SUID"`
}

type CytoElements struct {
	Nodes []CytoNode `json:"nodes"`
	Edges []CytoEdge `json:"edges"`
}

type CytoGraph struct {
	FormatVersion            string       `json:"format_version"`
	GeneratedBy              string       `json:"generated_by"`
	TargetCytoscapeJSVersion string       `json:"target_cytoscapejs_version"`
	Data                     CytoData     `json:"data"`
	Elements                 CytoElements `json:"elements"`
}

/*
 */

func GenerateCytoscapeJS(pg PwnGraph, alldetails bool) (CytoGraph, error) {
	g := CytoGraph{
		FormatVersion:            "1.0",
		GeneratedBy:              "AD Takeover",
		TargetCytoscapeJSVersion: "~2.1",
		Data: CytoData{
			SharedName: "AD Takeover",
			Name:       "AD Takeover",
		},
	}

	targetmap := make(map[*Object]struct{})
	for _, target := range pg.Targets {
		targetmap[target] = struct{}{}
	}
	nodeidmap := make(map[*Object]int)

	// Sort the nodes to get consistency
	sort.Slice(pg.Implicated, func(i, j int) bool {
		return bytes.Compare(pg.Implicated[i].GUID().Bytes(), pg.Implicated[j].GUID().Bytes()) == -1
	})

	// Sort the nodes to get consistency
	sort.Slice(pg.Connections, func(i, j int) bool {
		return bytes.Compare(
			pg.Connections[i].Source.GUID().Bytes(),
			pg.Connections[i].Source.GUID().Bytes()) == -1 ||
			bytes.Compare(pg.Connections[i].Target.GUID().Bytes(),
				pg.Connections[i].Target.GUID().Bytes()) == -1
	})

	nodecount := 0
	idcount := 0

	g.Elements.Nodes = make([]CytoNode, len(pg.Implicated))
	for _, object := range pg.Implicated {
		_, istarget := targetmap[object]

		nodeidmap[object] = idcount

		newnode := CytoNode{
			Data: map[string]interface{}{
				"id":                       fmt.Sprintf("n%v", idcount),
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
				if len(values) == 1 {
					newnode.Data[attr.String()] = values[0]
				} else {
					newnode.Data[attr.String()] = values
				}
			}
		}

		if istarget {
			newnode.Data["_querytarget"] = true
		}

		g.Elements.Nodes[nodecount] = newnode

		idcount++
		nodecount++
	}

	g.Elements.Edges = make([]CytoEdge, len(pg.Connections))
	edgecount := 0

	for _, connection := range pg.Connections {
		sourceid, found := nodeidmap[connection.Source]
		if !found {
			log.Error().Msg("Source object not found - this should never happen")
			continue
		}
		targetid, found := nodeidmap[connection.Target]
		if !found {
			log.Error().Msg("Target object not found - this should never happen")
			continue
		}

		edge := CytoEdge{
			Data: EdgeData{
				"id":     fmt.Sprintf("e%v", idcount),
				"source": fmt.Sprintf("n%v", sourceid),
				"target": fmt.Sprintf("n%v", targetid),
			},
		}
		for _, method := range connection.Methods.StringSlice() {
			edge.Data["method_"+method] = true
		}
		g.Elements.Edges[edgecount] = edge

		idcount++
		edgecount++
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
