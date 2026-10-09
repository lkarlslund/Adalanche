package mcpserver

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultRouteDepth = 6
	maxRouteDepth     = 12
	defaultRoutes     = 5
	maxRoutes         = 25
	defaultReachHops  = 3
	maxReachHops      = 10
	defaultHopSample  = 5
	maxHopSample      = 50
)

func (s *Server) addRouteTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "get_edge_path_details",
		Description: "Explain the edges along a sequence of node ids: each edge type, its probability, and why it exists (the ACE, group policy, machine collection or other cause recorded for it, and where that was set).",
	}, s.getEdgePathDetails)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "explain_routes",
		Description: "Show the shortest routes by which one node can reach a target node, or any node matching a filter such as (tag=hvt), " +
			"each step with its edge types, probabilities and causes. Use it to answer how an account can become a domain admin, and why.",
	}, s.explainRoutes)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "reach_summary",
		Description: "Count what a node can reach (out) or what can reach it (in), hop by hop, by node type, with a few examples per hop.",
	}, s.reachSummary)
}

// EdgeCause is one recorded reason an edge type exists.
type EdgeCause struct {
	Kind   string     `json:"kind"`
	Detail string     `json:"detail,omitempty"`
	About  *NodeBrief `json:"about,omitempty" jsonschema:"what the cause is about, such as the GPO"`
	SetOn  *NodeBrief `json:"set_on,omitempty" jsonschema:"where it was set, such as the object an inherited ACE came from"`
}

// EdgeTypeDetail is one type of an edge.
type EdgeTypeDetail struct {
	Type        string      `json:"type"`
	Probability int         `json:"probability"`
	Causes      []EdgeCause `json:"causes,omitempty"`
}

// edgeTypes explains an edge's types that are in only (all when blank).
func (s *Server) edgeTypes(g *engine.IndexedGraph, from, to *engine.Node, eb, only engine.EdgeBitmap) []EdgeTypeDetail {
	if !only.IsBlank() {
		eb = eb.Intersect(only)
	}
	causes := map[engine.Edge][]EdgeCause{}
	for _, p := range g.EdgeSources(from, to) {
		causes[p.Edge] = append(causes[p.Edge], EdgeCause{
			Kind:   p.Source.Kind.String(),
			Detail: p.Source.Detail,
			About:  s.briefOf(p.Source.About),
			SetOn:  s.briefOf(p.Source.Origin(from, to)),
		})
	}
	var result []EdgeTypeDetail
	for _, edge := range eb.Edges() {
		result = append(result, EdgeTypeDetail{edge.String(), int(edge.Probability(from, to, &eb)), causes[edge]})
	}
	slices.SortFunc(result, func(a, b EdgeTypeDetail) int {
		return cmp.Or(cmp.Compare(b.Probability, a.Probability), cmp.Compare(a.Type, b.Type))
	})
	return result
}

// RouteStep is one edge of a route.
type RouteStep struct {
	From      NodeBrief        `json:"from"`
	To        NodeBrief        `json:"to"`
	Reversed  bool             `json:"reversed,omitempty" jsonschema:"the edge runs from to to from"`
	EdgeTypes []EdgeTypeDetail `json:"edge_types"`
}

type pathInput struct {
	NodeIDs []string `json:"node_ids" jsonschema:"node ids, as tools give them, in order along the path"`
}

type pathOutput struct {
	Meta  Meta        `json:"meta"`
	Steps []RouteStep `json:"steps"`
}

func (s *Server) getEdgePathDetails(_ context.Context, _ *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, pathOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return nil, pathOutput{}, err
	}
	if len(in.NodeIDs) < 2 {
		return nil, pathOutput{}, fmt.Errorf("node_ids needs at least two nodes")
	}
	nodes := make([]*engine.Node, len(in.NodeIDs))
	for i, id := range in.NodeIDs {
		nodeID, err := s.parseNodeID(id)
		if err != nil {
			return nil, pathOutput{}, err
		}
		node, found := g.LookupNodeByID(nodeID)
		if !found {
			return nil, pathOutput{}, fmt.Errorf("node id %q not found", id)
		}
		nodes[i] = node
	}
	out := pathOutput{Meta: s.Meta()}
	for i := 1; i < len(nodes); i++ {
		from, to, reversed := nodes[i-1], nodes[i], false
		eb, found := g.GetEdge(from, to)
		if !found {
			if eb, found = g.GetEdge(to, from); !found {
				return nil, pathOutput{}, fmt.Errorf("no edge between %s and %s", in.NodeIDs[i-1], in.NodeIDs[i])
			}
			from, to, reversed = to, from, true
		}
		out.Steps = append(out.Steps, RouteStep{s.Brief(nodes[i-1]), s.Brief(nodes[i]), reversed, s.edgeTypes(g, from, to, eb, engine.EdgeBitmap{})})
	}
	return nil, out, nil
}

// routeEdges decides which edges routes may use: AQL's default edge types,
// or those named, no less likely than a minimum.
type routeEdges struct {
	types          engine.EdgeBitmap
	minProbability engine.Probability
}

func newRouteEdges(names []string, minProbability int) (routeEdges, error) {
	types, err := edgeFilter(names)
	if err != nil {
		return routeEdges{}, err
	}
	if types.IsBlank() {
		for _, edge := range engine.Edges() {
			if edge.DefaultF() || edge.DefaultM() || edge.DefaultL() {
				types = types.Set(edge)
			}
		}
	}
	return routeEdges{types, engine.Probability(max(minProbability, 0))}, nil
}

func (r routeEdges) usable(from, to *engine.Node, eb engine.EdgeBitmap) bool {
	eb = eb.Intersect(r.types)
	return !eb.IsBlank() && eb.MaxProbability(from, to) >= r.minProbability
}

type explainInput struct {
	From               NodeRef  `json:"from" jsonschema:"the node the routes start at"`
	To                 *NodeRef `json:"to,omitempty" jsonschema:"the target node; or give to_filter"`
	ToFilter           string   `json:"to_filter,omitempty" jsonschema:"LDAP style filter for the targets, such as (tag=hvt)"`
	EdgeTypes          []string `json:"edge_types,omitempty" jsonschema:"only edges of these types (default: the types queries use by default)"`
	MaxDepth           int      `json:"max_depth,omitempty" jsonschema:"longest route in edges (default 6, at most 12)"`
	MaxRoutes          int      `json:"max_routes,omitempty" jsonschema:"routes to list (default 5, at most 25)"`
	MinEdgeProbability int      `json:"min_edge_probability,omitempty" jsonschema:"leave out edges less likely than this percentage"`
}

// Route is one way from the source to a target.
type Route struct {
	Nodes []NodeBrief `json:"nodes"`
	Steps []RouteStep `json:"steps"`
}

type explainOutput struct {
	Meta       Meta      `json:"meta"`
	From       NodeBrief `json:"from"`
	Targets    int       `json:"targets"`
	Reachable  bool      `json:"reachable"`
	Shortest   int       `json:"shortest_length,omitempty"`
	Routes     []Route   `json:"routes,omitempty"`
	MoreRoutes bool      `json:"more_routes" jsonschema:"more shortest routes exist than are listed"`
}

func (s *Server) targets(g *engine.IndexedGraph, to *NodeRef, filter string) (map[*engine.Node]bool, error) {
	targets := map[*engine.Node]bool{}
	switch {
	case to != nil && to.text() != "":
		node, err := s.Lookup(g, *to)
		if err != nil {
			return nil, err
		}
		targets[node] = true
	case strings.TrimSpace(filter) != "":
		if err := checkFilter(filter); err != nil {
			return nil, err
		}
		selector, err := query.ParseLDAPQueryStrict(strings.TrimSpace(filter), g)
		if err != nil {
			return nil, err
		}
		query.NodeFilterExecute(selector, g).Iterate(func(n *engine.Node) bool {
			targets[n] = true
			return true
		})
	default:
		return nil, fmt.Errorf("give to or to_filter")
	}
	return targets, nil
}

func (s *Server) explainRoutes(ctx context.Context, _ *mcp.CallToolRequest, in explainInput) (*mcp.CallToolResult, explainOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return nil, explainOutput{}, err
	}
	source, err := s.Lookup(g, in.From)
	if err != nil {
		return nil, explainOutput{}, err
	}
	targets, err := s.targets(g, in.To, in.ToFilter)
	if err != nil {
		return nil, explainOutput{}, err
	}
	edges, err := newRouteEdges(in.EdgeTypes, in.MinEdgeProbability)
	if err != nil {
		return nil, explainOutput{}, err
	}
	maxDepth := clampLimit(in.MaxDepth, defaultRouteDepth, maxRouteDepth)
	out := explainOutput{Meta: s.Meta(), From: s.Brief(source), Targets: len(targets)}

	// How far each node is from the nearest target, found backwards from
	// the targets; the level that reaches the source is the last needed.
	distance := map[*engine.Node]int{}
	var frontier []*engine.Node
	for target := range targets {
		distance[target] = 0
		frontier = append(frontier, target)
	}
	steps := 0
	for depth := 1; depth <= maxDepth && len(frontier) > 0; depth++ {
		if _, found := distance[source]; found {
			break
		}
		var next []*engine.Node
		for _, node := range frontier {
			g.IterateEdges(node, engine.In, func(from *engine.Node, eb engine.EdgeBitmap) bool {
				steps++
				if _, seen := distance[from]; !seen && edges.usable(from, node, eb) {
					distance[from] = depth
					next = append(next, from)
				}
				return !cancelled(ctx, steps)
			})
		}
		if err := ctx.Err(); err != nil {
			return nil, explainOutput{}, err
		}
		frontier = next
	}
	length, reachable := distance[source]
	if !reachable {
		return nil, out, nil
	}
	out.Reachable, out.Shortest = true, length

	// Shortest routes run through nodes one nearer the targets at each step.
	limit := clampLimit(in.MaxRoutes, defaultRoutes, maxRoutes)
	var walk func(node *engine.Node, path []*engine.Node)
	walk = func(node *engine.Node, path []*engine.Node) {
		if len(out.Routes) > limit {
			return
		}
		path = append(path, node)
		if distance[node] == 0 {
			out.Routes = append(out.Routes, s.route(g, path, edges))
			return
		}
		type candidate struct {
			node        *engine.Node
			probability engine.Probability
		}
		var next []candidate
		g.IterateEdges(node, engine.Out, func(to *engine.Node, eb engine.EdgeBitmap) bool {
			if d, found := distance[to]; found && d == distance[node]-1 && edges.usable(node, to, eb) {
				eb = eb.Intersect(edges.types)
				next = append(next, candidate{to, eb.MaxProbability(node, to)})
			}
			return true
		})
		slices.SortFunc(next, func(a, b candidate) int {
			return cmp.Or(cmp.Compare(b.probability, a.probability), cmp.Compare(a.node.Label(), b.node.Label()), cmp.Compare(a.node.ID(), b.node.ID()))
		})
		for _, c := range next {
			walk(c.node, path)
		}
	}
	walk(source, nil)
	if len(out.Routes) > limit {
		out.Routes, out.MoreRoutes = out.Routes[:limit], true
	}
	return nil, out, nil
}

func (s *Server) route(g *engine.IndexedGraph, path []*engine.Node, edges routeEdges) Route {
	route := Route{}
	for i, node := range path {
		route.Nodes = append(route.Nodes, s.Brief(node))
		if i == 0 {
			continue
		}
		eb, _ := g.GetEdge(path[i-1], node)
		route.Steps = append(route.Steps, RouteStep{s.Brief(path[i-1]), s.Brief(node), false, s.edgeTypes(g, path[i-1], node, eb, edges.types)})
	}
	return route
}

type reachInput struct {
	NodeRef
	Direction          string   `json:"direction,omitempty" jsonschema:"out (default): what the node can reach; in: what can reach the node"`
	MaxHops            int      `json:"max_hops,omitempty" jsonschema:"hops to follow (default 3, at most 10)"`
	EdgeTypes          []string `json:"edge_types,omitempty" jsonschema:"only edges of these types (default: the types queries use by default)"`
	MinEdgeProbability int      `json:"min_edge_probability,omitempty" jsonschema:"leave out edges less likely than this percentage"`
	SamplePerHop       int      `json:"sample_per_hop,omitempty" jsonschema:"example nodes per hop (default 5, at most 50)"`
}

// HopSummary is what lies a number of hops away.
type HopSummary struct {
	Hop    int            `json:"hop"`
	Count  int            `json:"count"`
	Types  map[string]int `json:"types"`
	Sample []NodeBrief    `json:"sample"`
}

type reachOutput struct {
	Meta      Meta         `json:"meta"`
	Node      NodeBrief    `json:"node"`
	Direction string       `json:"direction"`
	Total     int          `json:"total_reached"`
	Hops      []HopSummary `json:"hops"`
}

func (s *Server) reachSummary(ctx context.Context, _ *mcp.CallToolRequest, in reachInput) (*mcp.CallToolResult, reachOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return nil, reachOutput{}, err
	}
	node, err := s.Lookup(g, in.NodeRef)
	if err != nil {
		return nil, reachOutput{}, err
	}
	edges, err := newRouteEdges(in.EdgeTypes, in.MinEdgeProbability)
	if err != nil {
		return nil, reachOutput{}, err
	}
	direction, name := engine.Out, "out"
	switch strings.ToLower(in.Direction) {
	case "", "out":
	case "in":
		direction, name = engine.In, "in"
	default:
		return nil, reachOutput{}, fmt.Errorf("direction must be out or in")
	}
	sample := clampLimit(in.SamplePerHop, defaultHopSample, maxHopSample)
	out := reachOutput{Meta: s.Meta(), Node: s.Brief(node), Direction: name}

	seen := map[*engine.Node]bool{node: true}
	frontier := []*engine.Node{node}
	steps := 0
	for hop := 1; hop <= clampLimit(in.MaxHops, defaultReachHops, maxReachHops) && len(frontier) > 0; hop++ {
		var next []*engine.Node
		for _, at := range frontier {
			g.IterateEdges(at, direction, func(other *engine.Node, eb engine.EdgeBitmap) bool {
				steps++
				from, to := at, other
				if direction == engine.In {
					from, to = other, at
				}
				if !seen[other] && edges.usable(from, to, eb) {
					seen[other] = true
					next = append(next, other)
				}
				return !cancelled(ctx, steps)
			})
		}
		if err := ctx.Err(); err != nil {
			return nil, reachOutput{}, err
		}
		if len(next) == 0 {
			break
		}
		summary := HopSummary{Hop: hop, Count: len(next), Types: map[string]int{}}
		for _, n := range next {
			summary.Types[n.Type().Lookup()]++
		}
		slices.SortFunc(next, func(a, b *engine.Node) int {
			return cmp.Or(cmp.Compare(a.Label(), b.Label()), cmp.Compare(a.ID(), b.ID()))
		})
		for _, n := range next[:min(len(next), sample)] {
			summary.Sample = append(summary.Sample, s.Brief(n))
		}
		out.Hops = append(out.Hops, summary)
		out.Total += len(next)
		frontier = next
	}
	return nil, out, nil
}
