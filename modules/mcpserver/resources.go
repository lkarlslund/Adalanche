package mcpserver

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/lkarlslund/adalanche/modules/aql"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) addResources() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "get_status",
		Description: "Whether data has finished loading, the version, and how many nodes of each type and edges the graph holds.",
	}, s.getStatus)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_schema",
		Description: "List node types, edge types with their descriptions, and attribute names, for writing filters and queries.",
	}, s.listSchema)

	for _, r := range []struct {
		uri, name, title, description string
		load                          func() any
	}{
		{"adalanche://schema/attributes", "attributes", "Attributes", "Attribute names in the graph schema.", func() any { return attributes() }},
		{"adalanche://schema/edges", "edges", "Edge types", "Edge types and what they mean.", func() any { return edgeTypeList() }},
		{"adalanche://schema/node-types", "node-types", "Node types", "Node types in the graph.", func() any { return nodeTypes() }},
		{"adalanche://queries/predefined", "predefined-queries", "Built-in queries", "Queries shipped with Adalanche.", func() any { return aql.PredefinedQueries }},
	} {
		s.mcp.AddResource(&mcp.Resource{URI: r.uri, Name: r.name, Title: r.title, Description: r.description, MIMEType: "application/json"},
			func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				body, err := json.MarshalIndent(r.load(), "", "  ")
				if err != nil {
					return nil, err
				}
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "application/json", Text: string(body)}}}, nil
			})
	}
}

type statusOutput struct {
	Meta       Meta           `json:"meta"`
	Version    string         `json:"version"`
	Statistics map[string]int `json:"statistics,omitempty"`
}

func (s *Server) getStatus(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, statusOutput, error) {
	g, err := s.Graph()
	out := statusOutput{Meta: s.Meta(), Version: version.ProgramVersionShort()}
	if err == nil {
		out.Statistics = map[string]int{"Nodes": g.Order(), "Edges": g.Size()}
		for nodeType, count := range g.Statistics() {
			if nodeType != 0 && count != 0 {
				out.Statistics[engine.NodeType(nodeType).Lookup()] = count
			}
		}
	}
	return nil, out, nil
}

// AttributeInfo describes an attribute.
type AttributeInfo struct {
	Name   string `json:"name"`
	Secret bool   `json:"secret,omitempty" jsonschema:"values are never returned and cannot be filtered on"`
}

// EdgeTypeInfo describes an edge type.
type EdgeTypeInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default,omitempty" jsonschema:"followed by queries and routes unless edge types are named"`
}

// NodeTypeInfo describes a node type.
type NodeTypeInfo struct {
	Name        string `json:"name" jsonschema:"the type as filters name it, such as (type=Person)"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
}

type schemaOutput struct {
	Meta       Meta            `json:"meta"`
	NodeTypes  []NodeTypeInfo  `json:"node_types"`
	EdgeTypes  []EdgeTypeInfo  `json:"edge_types"`
	Attributes []AttributeInfo `json:"attributes"`
}

func (s *Server) listSchema(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, schemaOutput, error) {
	return nil, schemaOutput{Meta: s.Meta(), NodeTypes: nodeTypes(), EdgeTypes: edgeTypeList(), Attributes: attributes()}, nil
}

func attributes() []AttributeInfo {
	var result []AttributeInfo
	for _, attr := range engine.Attributes() {
		if attr.HasFlag(engine.Hidden) {
			continue
		}
		result = append(result, AttributeInfo{Name: attr.String(), Secret: secret(attr)})
	}
	slices.SortFunc(result, func(a, b AttributeInfo) int { return strings.Compare(a.Name, b.Name) })
	return result
}

func edgeTypeList() []EdgeTypeInfo {
	var result []EdgeTypeInfo
	for _, info := range engine.EdgeInfos() {
		if info.Hidden {
			continue
		}
		result = append(result, EdgeTypeInfo{Name: info.Name, Description: info.Description, Default: info.DefaultF || info.DefaultM || info.DefaultL})
	}
	slices.SortFunc(result, func(a, b EdgeTypeInfo) int { return strings.Compare(a.Name, b.Name) })
	return result
}

func nodeTypes() []NodeTypeInfo {
	var result []NodeTypeInfo
	for _, info := range engine.NodeTypes() {
		// Types are named as filters match them: (type=Person).
		result = append(result, NodeTypeInfo{Name: info.Lookup, DisplayName: info.DisplayName, Description: info.Description})
	}
	slices.SortFunc(result, func(a, b NodeTypeInfo) int { return strings.Compare(a.Name, b.Name) })
	return result
}
