package mcpserver

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/lkarlslund/adalanche/modules/aql"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/persistence"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultNodeLimit   = 5000
	defaultResultNodes = 50
	maxResultNodes     = 500
	defaultResultEdges = 100
	maxResultEdges     = 1000
	memberSample       = 10
)

func (s *Server) addQueryTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "validate_aql",
		Description: "Check that an AQL query parses, without running it. get_doc with name aql describes the query language.",
	}, s.validateAQL)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "run_aql",
		Description: "Run an AQL query, such as REACH start:(tag=hvt)<-[()]{1,6}-end:(type=Person), and describe the result: totals, nodes per hop from the start nodes, " +
			"and the nodes nearest the start with the edges between them. Nodes that lead on to the start the same way are merged by default, so large results stay readable. " +
			"REACH finds every edge on a route and is fast; ACYCLIC lists paths and can be slow. get_doc with name aql describes the query language.",
	}, s.runAQL)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_saved_queries",
		Description: "List the built-in and saved queries.",
	}, s.listSavedQueries)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "run_saved_query",
		Description: "Run a built-in or saved query by name, described as run_aql does.",
	}, s.runSavedQuery)
}

type validateInput struct {
	Query string `json:"query" jsonschema:"the AQL query"`
}

type validateOutput struct {
	Meta  Meta `json:"meta"`
	Valid bool `json:"valid"`
}

func (s *Server) validateAQL(_ context.Context, _ *mcp.CallToolRequest, in validateInput) (*mcp.CallToolResult, validateOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return nil, validateOutput{}, err
	}
	if err := checkFilter(in.Query); err != nil {
		return nil, validateOutput{}, err
	}
	if _, err := aql.ParseAQLQuery(strings.TrimSpace(in.Query), g); err != nil {
		return nil, validateOutput{}, err
	}
	return nil, validateOutput{Meta: s.Meta(), Valid: true}, nil
}

// QueryOptions controls how a query runs and how much of its result is
// described.
type QueryOptions struct {
	Merge                     string `json:"merge,omitempty" jsonschema:"routes (default): merge nodes that lead on to the start nodes the same way; identical: merge only nodes with exactly the same edges; off"`
	NodeLimit                 int    `json:"node_limit,omitempty" jsonschema:"stop the search at this many nodes, counting merged nodes as one (default 5000; -1 for no limit)"`
	MaxDepth                  int    `json:"max_depth,omitempty" jsonschema:"longest route in edges (default: as the query says)"`
	MinEdgeProbability        int    `json:"min_edge_probability,omitempty" jsonschema:"leave out edges less likely than this percentage"`
	MinAccumulatedProbability int    `json:"min_accumulated_probability,omitempty" jsonschema:"leave out paths less likely than this percentage (not for REACH)"`
	MaxNodes                  int    `json:"max_nodes,omitempty" jsonschema:"nodes to describe, nearest the start first (default 50, at most 500)"`
	MaxEdges                  int    `json:"max_edges,omitempty" jsonschema:"edges between described nodes to list (default 100, at most 1000)"`
}

type runInput struct {
	Query string `json:"query" jsonschema:"the AQL query"`
	QueryOptions
}

// ResultNode is a node of a query result.
type ResultNode struct {
	NodeBrief
	Role string `json:"role,omitempty" jsonschema:"the query step it matched, such as start or end"`
	Hop  *int   `json:"hop,omitempty" jsonschema:"edges from the start nodes"`
	// Merged nodes stand for several nodes.
	Merged  int         `json:"merged,omitempty"`
	Members []NodeBrief `json:"members_sample,omitempty"`
	// Machines hold the local groups and accounts drawn as part of them.
	LocalNodes int    `json:"local_groups_and_accounts,omitempty"`
	Tier       string `json:"tier,omitempty"`
}

// ResultEdge is an edge of a query result.
type ResultEdge struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	EdgeTypes   []string `json:"edge_types"`
	Probability int      `json:"probability"`
	Flow        int      `json:"flow"`
}

type runOutput struct {
	Meta           Meta           `json:"meta"`
	Query          string         `json:"query"`
	TotalNodes     int            `json:"total_nodes" jsonschema:"nodes in the result, counting every member of a merged node and every node folded into a machine"`
	DrawnNodes     int            `json:"drawn_nodes" jsonschema:"nodes after merging and folding, as listed under nodes"`
	TotalEdges     int            `json:"total_edges" jsonschema:"edges between drawn nodes"`
	NodeTypes      map[string]int `json:"node_types"`
	NodesPerHop    map[string]int `json:"nodes_per_hop"`
	Incomplete     []string       `json:"incomplete,omitempty" jsonschema:"why the result holds less than everything the query matches"`
	Nodes          []ResultNode   `json:"nodes"`
	NodesTruncated bool           `json:"nodes_truncated"`
	Edges          []ResultEdge   `json:"edges"`
	EdgesTruncated bool           `json:"edges_truncated"`
}

func (s *Server) runAQL(ctx context.Context, _ *mcp.CallToolRequest, in runInput) (*mcp.CallToolResult, runOutput, error) {
	out, err := s.run(ctx, in.Query, in.QueryOptions)
	return nil, out, err
}

func (s *Server) run(ctx context.Context, queryText string, o QueryOptions) (runOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return runOutput{}, err
	}
	queryText = strings.TrimSpace(queryText)
	if err := checkFilter(queryText); err != nil {
		return runOutput{}, err
	}
	resolver, err := aql.ParseAQLQuery(queryText, g)
	if err != nil {
		return runOutput{}, err
	}

	opts := aql.NewResolverOptions()
	opts.Context = ctx
	switch strings.ToLower(o.Merge) {
	case "", "routes":
		opts.MergeNodes = aql.MergeRoutes
	case "identical":
		opts.MergeNodes = aql.MergeIdentical
	case "off":
		opts.MergeNodes = aql.MergeOff
	default:
		return runOutput{}, fmt.Errorf("merge must be routes, identical or off")
	}
	switch {
	case o.NodeLimit == 0:
		opts.NodeLimit = defaultNodeLimit
	case o.NodeLimit > 0:
		opts.NodeLimit = o.NodeLimit
	}
	if o.MaxDepth > 0 {
		opts.MaxDepth = o.MaxDepth
	}
	opts.MinEdgeProbability = engine.Probability(o.MinEdgeProbability)
	opts.MinAccumulatedProbability = engine.Probability(o.MinAccumulatedProbability)

	result, err := resolver.Resolve(opts)
	if err != nil {
		return runOutput{}, err
	}
	limits := result.Limits()
	for _, postprocess := range frontend.PostProcessors {
		*result = postprocess(*result)
	}
	out := s.describe(g, result, clampLimit(o.MaxNodes, defaultResultNodes, maxResultNodes), clampLimit(o.MaxEdges, defaultResultEdges, maxResultEdges))
	out.Meta, out.Query, out.Incomplete = s.Meta(), queryText, limits
	return out, nil
}

// describe summarises a result: every node counted, and the nodes nearest
// the start nodes described with the edges between them.
func (s *Server) describe(g *engine.IndexedGraph, result *graph.Graph[*engine.Node, engine.EdgeBitmap], maxNodes, maxEdges int) runOutput {
	out := runOutput{
		DrawnNodes:  result.Order(),
		TotalEdges:  result.Size(),
		NodeTypes:   map[string]int{},
		NodesPerHop: map[string]int{},
	}
	nodes := make([]ResultNode, 0, result.Order())
	for node, data := range result.Nodes() {
		var represented int
		for nodeType, count := range aql.Represented(node, data, g.LookupNodeByID) {
			out.NodeTypes[nodeType.Lookup()] += count
			represented += count
		}
		out.TotalNodes += represented
		rn := ResultNode{NodeBrief: s.Brief(node)}
		if hop, found := data["_hop"].(int); found {
			rn.Hop = &hop
			out.NodesPerHop[strconv.Itoa(hop)] += represented
		} else {
			out.NodesPerHop["unreached"] += represented
		}
		rn.Role, _ = data["reference"].(string)
		rn.Tier, _ = data["tier"].(string)
		if merged, _ := data["_merged"].(int); merged > 1 {
			rn.Merged = merged
			members, _ := data["_members"].([]aql.MergedMember)
			for _, member := range members[:min(len(members), memberSample)] {
				id, _ := strconv.ParseUint(strings.TrimPrefix(member.ID, "n"), 10, 32)
				if node, found := g.LookupNodeByID(engine.NodeID(id)); found {
					rn.Members = append(rn.Members, s.Brief(node))
				}
			}
		}
		folded, _ := data["_folded"].([]aql.MergedMember)
		rn.LocalNodes = len(folded)
		nodes = append(nodes, rn)
	}
	hopOf := func(n ResultNode) int {
		if n.Hop == nil {
			return 1 << 30
		}
		return *n.Hop
	}
	slices.SortFunc(nodes, func(a, b ResultNode) int {
		return cmp.Or(cmp.Compare(hopOf(a), hopOf(b)), cmp.Compare(b.Merged, a.Merged),
			cmp.Compare(a.Label, b.Label), cmp.Compare(a.NodeID, b.NodeID))
	})
	out.NodesTruncated = len(nodes) > maxNodes
	out.Nodes = nodes[:min(len(nodes), maxNodes)]

	described := map[string]bool{}
	for _, n := range out.Nodes {
		described[n.NodeID] = true
	}
	var edges []ResultEdge
	result.IterateEdges(func(source, target *engine.Node, eb engine.EdgeBitmap, flow int) bool {
		from, to := s.nodeID(source.ID()), s.nodeID(target.ID())
		if described[from] && described[to] {
			edges = append(edges, ResultEdge{from, to, eb.StringSlice(), int(eb.MaxProbability(source, target)), flow})
		}
		return true
	})
	slices.SortFunc(edges, func(a, b ResultEdge) int {
		return cmp.Or(cmp.Compare(b.Flow, a.Flow), cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To))
	})
	out.EdgesTruncated = len(edges) > maxEdges
	out.Edges = edges[:min(len(edges), maxEdges)]
	return out
}

// savedQueries returns the built-in queries and the saved ones, which
// override built-in ones of the same name.
func savedQueries() ([]aql.QueryDefinition, error) {
	byName := map[string]aql.QueryDefinition{}
	var defaultName string
	for _, q := range aql.PredefinedQueries {
		byName[q.Name] = q
		if q.Default {
			defaultName = q.Name
		}
	}
	saved, err := persistence.GetStorage[aql.QueryDefinition]("queries", false).List()
	if err != nil {
		return nil, err
	}
	for _, q := range saved {
		q.UserDefined = true
		q.Default = q.Name == defaultName
		byName[q.Name] = q
	}
	queries := slices.Collect(func(yield func(aql.QueryDefinition) bool) {
		for _, q := range byName {
			if !yield(q) {
				return
			}
		}
	})
	slices.SortFunc(queries, func(a, b aql.QueryDefinition) int {
		if a.UserDefined != b.UserDefined {
			if a.UserDefined {
				return 1
			}
			return -1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return queries, nil
}

type savedQueriesOutput struct {
	Meta    Meta                  `json:"meta"`
	Queries []aql.QueryDefinition `json:"queries"`
}

func (s *Server) listSavedQueries(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, savedQueriesOutput, error) {
	queries, err := savedQueries()
	if err != nil {
		return nil, savedQueriesOutput{}, err
	}
	return nil, savedQueriesOutput{Meta: s.Meta(), Queries: queries}, nil
}

type runSavedInput struct {
	Name string `json:"name" jsonschema:"the query's name, as list_saved_queries gives it"`
	QueryOptions
}

func (s *Server) runSavedQuery(ctx context.Context, _ *mcp.CallToolRequest, in runSavedInput) (*mcp.CallToolResult, runOutput, error) {
	queries, err := savedQueries()
	if err != nil {
		return nil, runOutput{}, err
	}
	i := slices.IndexFunc(queries, func(q aql.QueryDefinition) bool { return strings.EqualFold(q.Name, strings.TrimSpace(in.Name)) })
	if i < 0 {
		return nil, runOutput{}, fmt.Errorf("no query named %q; list_saved_queries lists them", in.Name)
	}
	q := queries[i]
	o := in.QueryOptions
	if o.MaxDepth == 0 && q.MaxDepth > 0 {
		o.MaxDepth = q.MaxDepth
	}
	if o.MinAccumulatedProbability == 0 {
		o.MinAccumulatedProbability = int(q.MinAccumulatedProbability)
	}
	out, err := s.run(ctx, q.Query, o)
	return nil, out, err
}
