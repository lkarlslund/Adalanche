package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/aql"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/lkarlslund/adalanche/modules/persistence"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultFindLimit = 25
	maxResultLimit   = 200
	maxAttrValues    = 20
	maxStringLength  = 256
)

var (
	mcpBind             = frontend.Command.Flags().String("mcp-bind", "", "Address and port of MCP server to bind to")
	mcpRedactionProfile = frontend.Command.Flags().String("mcp-redaction-profile", "strict", "Redaction profile for MCP responses")
)

func init() {
	frontend.AddAnalyzeHook(func(ws *frontend.WebService) error {
		if strings.TrimSpace(*mcpBind) == "" {
			return nil
		}

		srv, err := newServer(*mcpBind, *mcpRedactionProfile, ws)
		if err != nil {
			return err
		}
		return srv.start()
	})
}

type provider interface {
	Status() frontend.WebServiceStatus
}

type server struct {
	bind    string
	profile string
	ws      *frontend.WebService
	mcp     *mcp.Server
	http    *http.Server
	redact  redactor
}

func newServer(bind, profile string, ws *frontend.WebService) (*server, error) {
	r, err := newRedactor(profile)
	if err != nil {
		return nil, err
	}

	s := &server{
		bind:    bind,
		profile: profile,
		ws:      ws,
		redact:  r,
	}
	s.mcp = mcp.NewServer(&mcp.Implementation{
		Name:    "adalanche",
		Title:   "Adalanche MCP",
		Version: version.ProgramVersionShort(),
	}, nil)
	s.registerTools()
	s.registerResources()
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return s.mcp
	}, &mcp.StreamableHTTPOptions{
		JSONResponse:   true,
		SessionTimeout: 10 * time.Minute,
	})
	s.http = &http.Server{
		Addr:    bind,
		Handler: handler,
	}
	return s, nil
}

func (s *server) start() error {
	conn, err := net.Listen("tcp", s.bind)
	if err != nil {
		return err
	}
	go func() {
		if err := s.http.Serve(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			ui.Fatal().Msgf("Problem launching MCP listener: %v", err)
		}
	}()
	ui.Info().Msgf("Adalanche MCP listening at http://%s/ ...", s.bind)
	return nil
}

func (s *server) registerTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "get_status",
		Description: "Return Adalanche readiness, version, and graph statistics.",
	}, s.getStatus)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_schema",
		Description: "List node types, edge types, attribute names, and predefined queries.",
	}, s.listSchema)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "find_nodes",
		Description: "Find graph nodes using an LDAP-like Adalanche filter.",
	}, s.findNodes)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "get_node_details",
		Description: "Fetch one node by node ID, distinguished name, SID, GUID, or attribute.",
	}, s.getNodeDetails)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "get_edge_path_details",
		Description: "Fetch edge details for an ordered sequence of Adalanche node IDs.",
	}, s.getEdgePathDetails)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "validate_aql",
		Description: "Validate an Adalanche Query Language (AQL) expression.",
	}, s.validateAQL)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "run_aql",
		Description: "Execute an AQL query and return a bounded summary of the result graph.",
	}, s.runAQL)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_saved_queries",
		Description: "List built-in and persisted Adalanche queries.",
	}, s.listSavedQueries)
}

func (s *server) registerResources() {
	s.mcp.AddResource(&mcp.Resource{
		URI:         "adalanche://schema/attributes",
		Name:        "attributes",
		Title:       "Adalanche Attributes",
		Description: "Attribute names available in the loaded graph schema.",
		MIMEType:    "application/json",
	}, s.readStaticResource(func() any { return s.attributesResource() }))

	s.mcp.AddResource(&mcp.Resource{
		URI:         "adalanche://schema/edges",
		Name:        "edges",
		Title:       "Adalanche Edge Types",
		Description: "Edge types and metadata available in the graph.",
		MIMEType:    "application/json",
	}, s.readStaticResource(func() any { return s.edgesResource() }))

	s.mcp.AddResource(&mcp.Resource{
		URI:         "adalanche://schema/node-types",
		Name:        "node-types",
		Title:       "Adalanche Node Types",
		Description: "Node types available in the graph.",
		MIMEType:    "application/json",
	}, s.readStaticResource(func() any { return s.nodeTypesResource() }))

	s.mcp.AddResource(&mcp.Resource{
		URI:         "adalanche://queries/predefined",
		Name:        "predefined-queries",
		Title:       "Adalanche Predefined Queries",
		Description: "Built-in query catalog shipped with Adalanche.",
		MIMEType:    "application/json",
	}, s.readStaticResource(func() any { return s.predefinedQueriesResource() }))
}

func (s *server) readStaticResource(load func() any) mcp.ResourceHandler {
	return func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		body, err := json.MarshalIndent(load(), "", "  ")
		if err != nil {
			return nil, err
		}
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      req.Params.URI,
				MIMEType: "application/json",
				Text:     string(body),
			}},
		}, nil
	}
}

type emptyInput struct{}

type toolMeta struct {
	Status           string `json:"status"`
	Ready            bool   `json:"ready"`
	RedactionProfile string `json:"redaction_profile,omitempty"`
}

type statusOutput struct {
	Meta       toolMeta       `json:"meta"`
	Version    string         `json:"version"`
	Statistics map[string]int `json:"statistics"`
}

func (s *server) getStatus(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, statusOutput, error) {
	return nil, statusOutput{
		Meta: toolMeta{
			Status:           s.ws.Status().String(),
			Ready:            s.ws.Status() == frontend.Ready,
			RedactionProfile: s.profile,
		},
		Version:    version.ProgramVersionShort(),
		Statistics: graphStatistics(s.ws.SuperGraph),
	}, nil
}

type attributeSummary struct {
	Name   string `json:"name"`
	Hidden bool   `json:"hidden,omitempty"`
	Unique bool   `json:"unique,omitempty"`
	Single bool   `json:"single,omitempty"`
	Merge  bool   `json:"merge,omitempty"`
}

type edgeSummary struct {
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
	DefaultForFilter bool   `json:"default_filter,omitempty"`
	DefaultForGraph  bool   `json:"default_graph,omitempty"`
	DefaultForLayout bool   `json:"default_layout,omitempty"`
	Hidden           bool   `json:"hidden,omitempty"`
}

type nodeTypeSummary struct {
	Name           string `json:"name"`
	Lookup         string `json:"lookup"`
	DefaultEnabled bool   `json:"default_enabled"`
}

type schemaOutput struct {
	Meta              toolMeta              `json:"meta"`
	Attributes        []attributeSummary    `json:"attributes"`
	NodeTypes         []nodeTypeSummary     `json:"node_types"`
	EdgeTypes         []edgeSummary         `json:"edge_types"`
	PredefinedQueries []aql.QueryDefinition `json:"predefined_queries"`
}

func (s *server) listSchema(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, schemaOutput, error) {
	return nil, schemaOutput{
		Meta: toolMeta{
			Status:           s.ws.Status().String(),
			Ready:            s.ws.Status() == frontend.Ready,
			RedactionProfile: s.profile,
		},
		Attributes:        s.attributesResource(),
		NodeTypes:         s.nodeTypesResource(),
		EdgeTypes:         s.edgesResource(),
		PredefinedQueries: s.predefinedQueriesResource(),
	}, nil
}

type findNodesInput struct {
	Filter     string   `json:"filter" jsonschema:"LDAP-like Adalanche filter to evaluate; leave empty to list all nodes"`
	Attributes []string `json:"attributes,omitempty" jsonschema:"specific attributes to include in each node result"`
	OrderBy    string   `json:"order_by,omitempty" jsonschema:"attribute name to sort by"`
	Descending bool     `json:"descending,omitempty" jsonschema:"sort descending"`
	Skip       int      `json:"skip,omitempty" jsonschema:"number of matching nodes to skip"`
	Limit      int      `json:"limit,omitempty" jsonschema:"maximum number of nodes to return"`
}

type nodeSummary struct {
	NodeID            uint32              `json:"node_id"`
	Label             string              `json:"label"`
	Type              string              `json:"type"`
	PrimaryAttribute  string              `json:"primary_attribute,omitempty"`
	PrimaryValue      string              `json:"primary_value,omitempty"`
	DistinguishedName string              `json:"distinguished_name,omitempty"`
	Attributes        map[string][]string `json:"attributes,omitempty"`
	Redacted          []string            `json:"redacted_attributes,omitempty"`
}

type findNodesOutput struct {
	Meta      toolMeta      `json:"meta"`
	Total     int           `json:"total"`
	Returned  int           `json:"returned"`
	Truncated bool          `json:"truncated"`
	Nodes     []nodeSummary `json:"nodes"`
}

func (s *server) findNodes(_ context.Context, _ *mcp.CallToolRequest, in findNodesInput) (*mcp.CallToolResult, findNodesOutput, error) {
	g, err := s.readyGraph()
	if err != nil {
		return nil, findNodesOutput{}, err
	}

	var filtered *engine.IndexedGraph
	if strings.TrimSpace(in.Filter) == "" {
		filtered = g
	} else {
		selector, err := query.ParseLDAPQueryStrict(strings.TrimSpace(in.Filter), g)
		if err != nil {
			return nil, findNodesOutput{}, err
		}
		filtered = query.NodeFilterExecute(selector, g)
	}

	nodes := filtered.AsSlice()
	total := nodes.Len()
	if in.OrderBy != "" {
		nodes.Sort(engine.LookupAttribute(in.OrderBy), in.Descending)
	}
	nodes.Skip(max(in.Skip, 0))
	limit := clampLimit(in.Limit)
	nodes.Limit(limit)

	out := findNodesOutput{
		Meta: toolMeta{
			Status:           s.ws.Status().String(),
			Ready:            true,
			RedactionProfile: s.profile,
		},
		Total:     total,
		Returned:  nodes.Len(),
		Truncated: total > max(in.Skip, 0)+nodes.Len(),
		Nodes:     make([]nodeSummary, 0, nodes.Len()),
	}
	nodes.Iterate(func(n *engine.Node) bool {
		out.Nodes = append(out.Nodes, s.nodeSummary(n, in.Attributes))
		return true
	})
	return nil, out, nil
}

type getNodeDetailsInput struct {
	LocateBy string `json:"locate_by" jsonschema:"one of: nodeid, id, dn, distinguishedname, sid, guid, or an attribute name"`
	ID       string `json:"id" jsonschema:"identifier value to resolve"`
}

type getNodeDetailsOutput struct {
	Meta toolMeta    `json:"meta"`
	Node nodeSummary `json:"node"`
}

func (s *server) getNodeDetails(_ context.Context, _ *mcp.CallToolRequest, in getNodeDetailsInput) (*mcp.CallToolResult, getNodeDetailsOutput, error) {
	g, err := s.readyGraph()
	if err != nil {
		return nil, getNodeDetailsOutput{}, err
	}
	node, err := s.lookupNode(g, in.LocateBy, in.ID)
	if err != nil {
		return nil, getNodeDetailsOutput{}, err
	}
	return nil, getNodeDetailsOutput{
		Meta: toolMeta{
			Status:           s.ws.Status().String(),
			Ready:            true,
			RedactionProfile: s.profile,
		},
		Node: s.nodeSummary(node, nil),
	}, nil
}

type getEdgePathDetailsInput struct {
	NodeIDs []uint32 `json:"node_ids" jsonschema:"ordered list of Adalanche node IDs describing a path"`
}

type pathEdgeSummary struct {
	From      uint32   `json:"from"`
	To        uint32   `json:"to"`
	Methods   []string `json:"methods"`
	MaxProb   int8     `json:"max_probability"`
	FromLabel string   `json:"from_label"`
	ToLabel   string   `json:"to_label"`
}

type getEdgePathDetailsOutput struct {
	Meta  toolMeta          `json:"meta"`
	Edges []pathEdgeSummary `json:"edges"`
}

func (s *server) getEdgePathDetails(_ context.Context, _ *mcp.CallToolRequest, in getEdgePathDetailsInput) (*mcp.CallToolResult, getEdgePathDetailsOutput, error) {
	g, err := s.readyGraph()
	if err != nil {
		return nil, getEdgePathDetailsOutput{}, err
	}
	if len(in.NodeIDs) < 2 {
		return nil, getEdgePathDetailsOutput{}, fmt.Errorf("node_ids must contain at least 2 entries")
	}

	nodes := make([]*engine.Node, len(in.NodeIDs))
	for i, id := range in.NodeIDs {
		node, found := g.LookupNodeByID(engine.NodeID(id))
		if !found {
			return nil, getEdgePathDetailsOutput{}, fmt.Errorf("node id %d not found", id)
		}
		nodes[i] = node
	}

	out := getEdgePathDetailsOutput{
		Meta: toolMeta{
			Status:           s.ws.Status().String(),
			Ready:            true,
			RedactionProfile: s.profile,
		},
		Edges: make([]pathEdgeSummary, 0, len(nodes)-1),
	}
	for i := 1; i < len(nodes); i++ {
		eb, found := g.GetEdge(nodes[i-1], nodes[i])
		if !found {
			return nil, getEdgePathDetailsOutput{}, fmt.Errorf("edge between %d and %d not found", in.NodeIDs[i-1], in.NodeIDs[i])
		}
		out.Edges = append(out.Edges, pathEdgeSummary{
			From:      in.NodeIDs[i-1],
			To:        in.NodeIDs[i],
			Methods:   eb.StringSlice(),
			MaxProb:   int8(eb.MaxProbability(nodes[i-1], nodes[i])),
			FromLabel: nodes[i-1].Label(),
			ToLabel:   nodes[i].Label(),
		})
	}
	return nil, out, nil
}

type validateAQLInput struct {
	Query string `json:"query" jsonschema:"AQL query to validate"`
}

type validateAQLOutput struct {
	Meta  toolMeta `json:"meta"`
	Valid bool     `json:"valid"`
}

func (s *server) validateAQL(_ context.Context, _ *mcp.CallToolRequest, in validateAQLInput) (*mcp.CallToolResult, validateAQLOutput, error) {
	g, err := s.readyGraph()
	if err != nil {
		return nil, validateAQLOutput{}, err
	}
	if _, err := aql.ParseAQLQuery(strings.TrimSpace(in.Query), g); err != nil {
		return nil, validateAQLOutput{}, err
	}
	return nil, validateAQLOutput{
		Meta: toolMeta{
			Status:           s.ws.Status().String(),
			Ready:            true,
			RedactionProfile: s.profile,
		},
		Valid: true,
	}, nil
}

type runAQLInput struct {
	Query                     string `json:"query" jsonschema:"AQL query to execute"`
	MaxDepth                  int    `json:"max_depth,omitempty" jsonschema:"maximum traversal depth; -1 means unlimited"`
	NodeLimit                 int    `json:"node_limit,omitempty" jsonschema:"limit the number of returned result nodes"`
	MinEdgeProbability        int8   `json:"min_edge_probability,omitempty" jsonschema:"minimum per-edge probability"`
	MinAccumulatedProbability int8   `json:"min_accumulated_probability,omitempty" jsonschema:"minimum accumulated path probability"`
	PruneIslands              bool   `json:"prune_islands,omitempty" jsonschema:"remove isolated nodes from the result graph"`
}

type sampledEdge struct {
	From    uint32   `json:"from"`
	To      uint32   `json:"to"`
	Methods []string `json:"methods"`
	MaxProb int8     `json:"max_probability"`
}

type runAQLOutput struct {
	Meta         toolMeta       `json:"meta"`
	TotalNodes   int            `json:"total_nodes"`
	TotalEdges   int            `json:"total_edges"`
	ResultTypes  map[string]int `json:"result_types"`
	SampledNodes []nodeSummary  `json:"sampled_nodes"`
	SampledEdges []sampledEdge  `json:"sampled_edges"`
}

func (s *server) runAQL(_ context.Context, _ *mcp.CallToolRequest, in runAQLInput) (*mcp.CallToolResult, runAQLOutput, error) {
	g, err := s.readyGraph()
	if err != nil {
		return nil, runAQLOutput{}, err
	}
	resolver, err := aql.ParseAQLQuery(strings.TrimSpace(in.Query), g)
	if err != nil {
		return nil, runAQLOutput{}, err
	}

	opts := aql.NewResolverOptions()
	opts.MaxDepth = in.MaxDepth
	opts.NodeLimit = clampLimitOrUnlimited(in.NodeLimit)
	opts.MinEdgeProbability = engine.Probability(in.MinEdgeProbability)
	opts.MinAccumulatedProbability = engine.Probability(in.MinAccumulatedProbability)
	opts.PruneIslands = in.PruneIslands
	if opts.MaxDepth == 0 {
		opts.MaxDepth = -1
	}

	results, err := resolver.Resolve(opts)
	if err != nil {
		return nil, runAQLOutput{}, err
	}

	if opts.PruneIslands {
		for _, island := range results.Islands() {
			results.DeleteNode(island)
		}
	}

	out := runAQLOutput{
		Meta: toolMeta{
			Status:           s.ws.Status().String(),
			Ready:            true,
			RedactionProfile: s.profile,
		},
		TotalNodes:   results.Order(),
		TotalEdges:   results.Size(),
		ResultTypes:  make(map[string]int),
		SampledNodes: make([]nodeSummary, 0, min(results.Order(), defaultFindLimit)),
		SampledEdges: make([]sampledEdge, 0, min(results.Size(), defaultFindLimit)),
	}

	nodes := make([]*engine.Node, 0, results.Order())
	for node := range results.Nodes() {
		nodes = append(nodes, node)
		out.ResultTypes[node.Type().String()]++
	}
	slices.SortFunc(nodes, func(a, b *engine.Node) int {
		if a.ID() < b.ID() {
			return -1
		}
		if a.ID() > b.ID() {
			return 1
		}
		return 0
	})
	for i, node := range nodes {
		if i >= defaultFindLimit {
			break
		}
		out.SampledNodes = append(out.SampledNodes, s.nodeSummary(node, nil))
	}
	results.IterateEdges(func(source, target *engine.Node, edge engine.EdgeBitmap, _ int) bool {
		if len(out.SampledEdges) >= defaultFindLimit {
			return false
		}
		out.SampledEdges = append(out.SampledEdges, sampledEdge{
			From:    uint32(source.ID()),
			To:      uint32(target.ID()),
			Methods: edge.StringSlice(),
			MaxProb: int8(edge.MaxProbability(source, target)),
		})
		return true
	})
	return nil, out, nil
}

type listSavedQueriesOutput struct {
	Meta    toolMeta              `json:"meta"`
	Queries []aql.QueryDefinition `json:"queries"`
}

func (s *server) listSavedQueries(_ context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, listSavedQueriesOutput, error) {
	queryMap := make(map[string]aql.QueryDefinition)
	var defaultName string
	for _, q := range aql.PredefinedQueries {
		queryMap[q.Name] = q
		if q.Default {
			defaultName = q.Name
		}
	}

	userQueries := persistence.GetStorage[aql.QueryDefinition]("queries", false)
	uq, err := userQueries.List()
	if err != nil {
		return nil, listSavedQueriesOutput{}, err
	}
	for _, q := range uq {
		q.UserDefined = true
		if q.Name == defaultName {
			q.Default = true
		}
		queryMap[q.Name] = q
	}

	queries := make([]aql.QueryDefinition, 0, len(queryMap))
	for _, q := range queryMap {
		queries = append(queries, q)
	}
	slices.SortFunc(queries, func(a, b aql.QueryDefinition) int {
		if a.UserDefined != b.UserDefined {
			if a.UserDefined {
				return 1
			}
			return -1
		}
		return strings.Compare(a.Name, b.Name)
	})

	return nil, listSavedQueriesOutput{
		Meta: toolMeta{
			Status:           s.ws.Status().String(),
			Ready:            s.ws.Status() == frontend.Ready,
			RedactionProfile: s.profile,
		},
		Queries: queries,
	}, nil
}

func (s *server) readyGraph() (*engine.IndexedGraph, error) {
	if s.ws.Status() != frontend.Ready || s.ws.SuperGraph == nil {
		return nil, fmt.Errorf("adalanche data is not ready")
	}
	return s.ws.SuperGraph, nil
}

func (s *server) lookupNode(g *engine.IndexedGraph, locateBy, id string) (*engine.Node, error) {
	switch strings.ToLower(strings.TrimSpace(locateBy)) {
	case "id":
		var index int64
		if _, err := fmt.Sscan(id, &index); err != nil {
			return nil, fmt.Errorf("invalid index: %w", err)
		}
		node, found := g.IndexToNode(engine.NodeIndex(index))
		if !found {
			return nil, fmt.Errorf("node index %d not found", index)
		}
		return node, nil
	case "nodeid":
		var nodeID int64
		if _, err := fmt.Sscan(id, &nodeID); err != nil {
			return nil, fmt.Errorf("invalid node id: %w", err)
		}
		node, found := g.LookupNodeByID(engine.NodeID(nodeID))
		if !found {
			return nil, fmt.Errorf("node id %d not found", nodeID)
		}
		return node, nil
	case "dn", "distinguishedname":
		node, found := g.Find(engine.DistinguishedName, engine.NV(id))
		if !found {
			return nil, fmt.Errorf("distinguished name not found")
		}
		return node, nil
	case "sid":
		sid, err := windowssecurity.ParseStringSID(id)
		if err != nil {
			return nil, err
		}
		node, found := g.Find(engine.ObjectSid, engine.NV(sid))
		if !found {
			return nil, fmt.Errorf("sid not found")
		}
		return node, nil
	case "guid":
		guid, err := uuid.FromString(id)
		if err != nil {
			return nil, err
		}
		node, found := g.Find(engine.ObjectGUID, engine.NV(guid))
		if !found {
			return nil, fmt.Errorf("guid not found")
		}
		return node, nil
	default:
		attr := engine.LookupAttribute(locateBy)
		if attr == engine.NonExistingAttribute {
			return nil, fmt.Errorf("unknown locate_by attribute %q", locateBy)
		}
		node, found := g.Find(attr, engine.NV(id))
		if !found {
			return nil, fmt.Errorf("node not found")
		}
		return node, nil
	}
}

func (s *server) nodeSummary(node *engine.Node, selected []string) nodeSummary {
	attrMap, redacted := s.redactedAttributes(node, selected)
	attr, value := node.PrimaryID()
	return nodeSummary{
		NodeID:            uint32(node.ID()),
		Label:             node.Label(),
		Type:              node.Type().String(),
		PrimaryAttribute:  attr.String(),
		PrimaryValue:      sanitizeValue(value.String()),
		DistinguishedName: sanitizeValue(node.DN()),
		Attributes:        attrMap,
		Redacted:          redacted,
	}
}

func (s *server) redactedAttributes(node *engine.Node, selected []string) (map[string][]string, []string) {
	all := node.ValueMap()
	names := make([]string, 0, len(all))
	if len(selected) > 0 {
		names = append(names, selected...)
	} else {
		for name := range all {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	result := make(map[string][]string)
	var redacted []string
	for _, name := range names {
		values, found := all[name]
		if !found {
			continue
		}
		if masked, ok := s.redact.mask(name, values); ok {
			result[name] = masked
			redacted = append(redacted, name)
			continue
		}
		if len(values) > maxAttrValues {
			values = values[:maxAttrValues]
		}
		clean := make([]string, 0, len(values))
		for _, value := range values {
			clean = append(clean, sanitizeValue(value))
		}
		result[name] = clean
	}
	return result, redacted
}

func sanitizeValue(value string) string {
	if !util.IsPrintableString(value) {
		value = util.Hexify(value)
	}
	if len(value) > maxStringLength {
		return value[:maxStringLength] + " ..."
	}
	return value
}

func graphStatistics(g *engine.IndexedGraph) map[string]int {
	stats := make(map[string]int)
	if g == nil {
		return stats
	}
	for objectType, count := range g.Statistics() {
		if objectType == 0 || count == 0 {
			continue
		}
		stats[engine.NodeType(objectType).String()] = count
	}
	stats["Nodes"] = g.Order()
	stats["Edges"] = g.Size()
	return stats
}

func (s *server) attributesResource() []attributeSummary {
	attrs := engine.Attributes()
	result := make([]attributeSummary, 0, len(attrs))
	for _, attr := range attrs {
		result = append(result, attributeSummary{
			Name:   attr.String(),
			Hidden: attr.HasFlag(engine.Hidden),
			Unique: attr.HasFlag(engine.Unique),
			Single: attr.HasFlag(engine.Single),
			Merge:  attr.HasFlag(engine.Merge),
		})
	}
	slices.SortFunc(result, func(a, b attributeSummary) int {
		return strings.Compare(a.Name, b.Name)
	})
	return result
}

func (s *server) edgesResource() []edgeSummary {
	infos := engine.EdgeInfos()
	result := make([]edgeSummary, 0, len(infos))
	for _, info := range infos {
		result = append(result, edgeSummary{
			Name:             info.Name,
			Description:      info.Description,
			DefaultForFilter: info.DefaultF,
			DefaultForGraph:  info.DefaultM,
			DefaultForLayout: info.DefaultL,
			Hidden:           info.Hidden,
		})
	}
	slices.SortFunc(result, func(a, b edgeSummary) int {
		return strings.Compare(a.Name, b.Name)
	})
	return result
}

func (s *server) nodeTypesResource() []nodeTypeSummary {
	types := engine.NodeTypes()
	result := make([]nodeTypeSummary, 0, len(types))
	for _, info := range types {
		result = append(result, nodeTypeSummary{
			Name:           info.Name,
			Lookup:         info.Lookup,
			DefaultEnabled: info.DefaultEnabled,
		})
	}
	slices.SortFunc(result, func(a, b nodeTypeSummary) int {
		return strings.Compare(a.Name, b.Name)
	})
	return result
}

func (s *server) predefinedQueriesResource() []aql.QueryDefinition {
	result := append([]aql.QueryDefinition(nil), aql.PredefinedQueries...)
	slices.SortFunc(result, func(a, b aql.QueryDefinition) int {
		return strings.Compare(a.Name, b.Name)
	})
	return result
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return defaultFindLimit
	}
	if limit > maxResultLimit {
		return maxResultLimit
	}
	return limit
}

func clampLimitOrUnlimited(limit int) int {
	if limit <= 0 {
		return -1
	}
	if limit > maxResultLimit {
		return maxResultLimit
	}
	return limit
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
