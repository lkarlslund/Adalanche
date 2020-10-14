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
		stringmethods := make([]string, len(connection.Methods))
		for i, method := range connection.Methods {
			stringmethods[i] = method.String()
		}
		fmt.Fprintf(df, "    \"%v\" -> \"%v\" [label=\"%v\"];\n", connection.Source.GUID(), connection.Target.GUID(), strings.Join(stringmethods, ", "))
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
	Data    map[string]interface{} `json:"data"`
	Classes []string               `json:"classes"`
}

type EdgeData struct {
	Id                   string   `json:"id"`
	Source               string   `json:"source"`
	Target               string   `json:"target"`
	Methods              []string `json:"methods,omitempty"`
	PwnACLContainsDeny   bool     `json:"pwn_aclcontainsdeny,omitempty"`
	PwnOwns              bool     `json:"pwn_owns,omitempty"`
	PwnMemberOfGroup     bool     `json:"pwn_memberofgroup,omitempty"`
	PwnGenericAll        bool     `json:"pwn_genericall,omitempty"`
	PwnWriteAll          bool     `json:"pwn_writeall,omitempty"`
	PwnWritePropertyAll  bool     `json:"pwn_writepropertyall,omitempty"`
	PwnTakeOwnership     bool     `json:"pwn_takeownership,omitempty"`
	PwnWriteDACL         bool     `json:"pwn_writedacl,omitempty"`
	PwnResetPassword     bool     `json:"pwn_resetpassword,omitempty"`
	PwnAddMember         bool     `json:"pwn_addmember,omitempty"`
	PwnAllExtendedRights bool     `json:"pwn_allextendedrights,omitempty"`
}

type CytoEdge struct {
	Data    EdgeData `json:"data"`
	Classes []string `json:"classes"`
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
				"id":                     fmt.Sprintf("n%v", idcount),
				"label":                  object.OneAttr(Name),
				DistinguishedName.Name(): object.DN(),
				Name.Name():              object.OneAttr(Name),
				DisplayName.Name():       object.OneAttr(DisplayName),
				Description.Name():       object.OneAttr(Description),
				ObjectSid.Name():         object.SID().String(),
				SAMAccountName.Name():    object.OneAttr(SAMAccountName),
			}}

		if alldetails {
			for attr, values := range object.Attributes {
				if len(values) == 1 {
					newnode.Data[attr.Name()] = values[0]
				} else {
					newnode.Data[attr.Name()] = values
				}
			}
		}

		if istarget {
			newnode.Data["_querytarget"] = true
		}
		for key, value := range object.Meta() {
			newnode.Data[key] = value
		}

		g.Elements.Nodes[nodecount] = newnode

		idcount++
		nodecount++
	}

	g.Elements.Edges = make([]CytoEdge, len(pg.Connections))
	edgecount := 0

	for _, connection := range pg.Connections {
		stringmethods := make([]string, len(connection.Methods))
		for i, method := range connection.Methods {
			stringmethods[i] = method.String()
		}

		sourceid, found := nodeidmap[connection.Source]
		if !found {
			log.Error().Msg("Source object not found - this should never happen")
		}
		targetid, found := nodeidmap[connection.Target]
		if !found {
			log.Error().Msg("Target object not found - this should never happen")
		}

		g.Elements.Edges[edgecount] = CytoEdge{
			Data: EdgeData{
				Id:                   fmt.Sprintf("e%v", idcount),
				Source:               fmt.Sprintf("n%v", sourceid),
				Target:               fmt.Sprintf("n%v", targetid),
				Methods:              stringmethods,
				PwnACLContainsDeny:   StringInSlice("ACLContainsDeny", stringmethods),
				PwnOwns:              StringInSlice("Owns", stringmethods),
				PwnGenericAll:        StringInSlice("GenericAll", stringmethods),
				PwnWriteAll:          StringInSlice("WriteAll", stringmethods),
				PwnWritePropertyAll:  StringInSlice("WritePropertyAll", stringmethods),
				PwnTakeOwnership:     StringInSlice("TakeOwnership", stringmethods),
				PwnWriteDACL:         StringInSlice("WriteDACL", stringmethods),
				PwnResetPassword:     StringInSlice("ResetPassword", stringmethods),
				PwnAddMember:         StringInSlice("AddMember", stringmethods),
				PwnMemberOfGroup:     StringInSlice("MemberOfGroup", stringmethods),
				PwnAllExtendedRights: StringInSlice("AllExtendedRights", stringmethods),
			},
		}
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
