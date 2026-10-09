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
	// maxRouteExpansions bounds the search for routes no deny refuses.
	maxRouteExpansions = 200000
	maxRoutes          = 25
	defaultReachHops   = 3
	maxReachHops       = 10
	defaultHopSample   = 5
	maxHopSample       = 50
)

func (s *Server) addRouteTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "get_edge_path_details",
		Description: "Explain the edges along a sequence of node ids: each edge type, its probability, and why it exists (the ACE, group policy, machine collection or other cause recorded for it, and where that was set). For an ACE, get_acl shows it in full. " +
			"Each step names the account acting there, the nearest account before it, and marks edge types a deny refuses to that account.",
	}, s.getEdgePathDetails)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "explain_routes",
		Description: "Show the shortest routes by which one node can reach a target node, or any node matching a filter such as (tag=hvt), " +
			"each step with its edge types, probabilities and causes. Use it to answer how an account can become a domain admin, and why. " +
			"Routes a deny refuses are left out: an edge from a group is refused to a member when a deny for the member, or for another group it is in, comes first in the target's ACL.",
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
	// ACE and ACEAttribute point get_acl at the ACE behind the cause.
	ACE          *int   `json:"ace,omitempty" jsonschema:"the index of the ACE behind the cause in the target's descriptor; get_acl with the target and this index shows it"`
	ACEAttribute string `json:"ace_attribute,omitempty" jsonschema:"the attribute holding that descriptor, to pass to get_acl, when it is not the object's own"`
}

// EdgeTypeDetail is one type of an edge.
type EdgeTypeDetail struct {
	Type        string      `json:"type"`
	Probability int         `json:"probability"`
	Refused     bool        `json:"refused,omitempty" jsonschema:"a deny refuses this edge type to the account acting on the route"`
	Causes      []EdgeCause `json:"causes,omitempty"`
}

// edgeTypes explains an edge's types that are in only (all when blank),
// marking those in refused.
func (s *Server) edgeTypes(g *engine.IndexedGraph, from, to *engine.Node, eb, only, refused engine.EdgeBitmap) []EdgeTypeDetail {
	if !only.IsBlank() {
		eb = eb.Intersect(only)
	}
	causes := map[engine.Edge][]EdgeCause{}
	for _, p := range g.EdgeSources(from, to) {
		cause := EdgeCause{
			Kind:   p.Source.Kind.String(),
			Detail: p.Source.Detail,
			About:  s.briefOf(p.Source.About),
			SetOn:  s.briefOf(p.Source.Origin(from, to)),
		}
		if attr, index, ok := causeACE(p.Source.Detail); ok {
			cause.ACE = &index
			if attr != engine.NTSecurityDescriptor.String() {
				cause.ACEAttribute = attr
			}
		}
		causes[p.Edge] = append(causes[p.Edge], cause)
	}
	var result []EdgeTypeDetail
	for _, edge := range eb.Edges() {
		result = append(result, EdgeTypeDetail{edge.String(), int(edge.Probability(from, to, &eb)), refused.IsSet(edge), causes[edge]})
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
	ActingAs  *NodeBrief       `json:"acting_as,omitempty" jsonschema:"the account acting at this step: the nearest account at or before from; absent when the route starts at a group, standing for every member"`
	Refused   bool             `json:"refused,omitempty" jsonschema:"a deny refuses every edge type of this step to the account acting there"`
	EdgeTypes []EdgeTypeDetail `json:"edge_types"`
}

type pathInput struct {
	NodeIDs []string `json:"node_ids" jsonschema:"node ids, as tools give them, in order along the path"`
}

type pathOutput struct {
	Meta    Meta        `json:"meta"`
	Refused bool        `json:"refused,omitempty" jsonschema:"a deny refuses some step of the path to the account acting there, so the path does not hold"`
	Steps   []RouteStep `json:"steps"`
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
	routes := engine.NewRouteChecker(g)
	// Who acts is followed only along a path that runs with its edges.
	var actor *engine.Node
	forward := true
	for i := 1; i < len(nodes); i++ {
		from, to, reversed := nodes[i-1], nodes[i], false
		eb, found := g.GetEdge(from, to)
		if !found {
			if eb, found = g.GetEdge(to, from); !found {
				return nil, pathOutput{}, fmt.Errorf("no edge between %s and %s", in.NodeIDs[i-1], in.NodeIDs[i])
			}
			from, to, reversed = to, from, true
			forward = false
		}
		step := RouteStep{From: s.Brief(nodes[i-1]), To: s.Brief(nodes[i]), Reversed: reversed}
		var refused engine.EdgeBitmap
		if forward {
			if engine.IsActor(from) {
				actor = from
			}
			if actor != nil {
				step.ActingAs = s.briefOf(actor)
			}
			refused = routes.Refused(actor, from, to, eb)
			step.Refused = refused == eb
			out.Refused = out.Refused || step.Refused
		}
		step.EdgeTypes = s.edgeTypes(g, from, to, eb, engine.EdgeBitmap{}, refused)
		out.Steps = append(out.Steps, step)
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
	Meta         Meta      `json:"meta"`
	From         NodeBrief `json:"from"`
	Targets      int       `json:"targets"`
	Reachable    bool      `json:"reachable"`
	Shortest     int       `json:"shortest_length,omitempty"`
	Routes       []Route   `json:"routes,omitempty"`
	MoreRoutes   bool      `json:"more_routes" jsonschema:"more shortest routes exist than are listed"`
	RefusedSteps int       `json:"refused_steps,omitempty" jsonschema:"steps left out of routes because a deny refuses them to the account acting there"`
	Limited      bool      `json:"search_limited,omitempty" jsonschema:"the search stopped early; routes may be missing"`
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
	// the targets one level at a time, as far as routes need.
	distance := map[*engine.Node]int{}
	var frontier []*engine.Node
	for target := range targets {
		distance[target] = 0
		frontier = append(frontier, target)
	}
	level, steps := 0, 0
	extend := func() {
		level++
		var next []*engine.Node
		for _, node := range frontier {
			g.IterateEdges(node, engine.In, func(from *engine.Node, eb engine.EdgeBitmap) bool {
				steps++
				if _, seen := distance[from]; !seen && edges.usable(from, node, eb) {
					distance[from] = level
					next = append(next, from)
				}
				return !cancelled(ctx, steps)
			})
		}
		frontier = next
	}
	for level < maxDepth && len(frontier) > 0 {
		if _, found := distance[source]; found {
			break
		}
		extend()
	}
	if err := ctx.Err(); err != nil {
		return nil, explainOutput{}, err
	}
	shortest, reachable := distance[source]
	if !reachable {
		return nil, out, nil
	}

	// The shortest routes are listed. The distances leave denies out, so
	// routes of each length are searched in turn until one holds, skipping
	// steps a deny refuses to the account acting there; the distances only
	// prune.
	routes := engine.NewRouteChecker(g)
	limit := clampLimit(in.MaxRoutes, defaultRoutes, maxRoutes)
	expansions := 0
	var walk func(node, actor *engine.Node, path []*engine.Node, remaining int)
	walk = func(node, actor *engine.Node, path []*engine.Node, remaining int) {
		if len(out.Routes) > limit || out.Limited {
			return
		}
		path = append(path, node)
		if engine.IsActor(node) {
			actor = node
		}
		if distance[node] == 0 {
			if remaining == 0 {
				out.Routes = append(out.Routes, s.route(g, path, edges, routes))
			}
			return
		}
		if expansions++; expansions > maxRouteExpansions || cancelled(ctx, expansions) {
			out.Limited = true
			return
		}
		type candidate struct {
			node        *engine.Node
			probability engine.Probability
		}
		var next []candidate
		g.IterateEdges(node, engine.Out, func(to *engine.Node, eb engine.EdgeBitmap) bool {
			if d, found := distance[to]; !found || d > remaining-1 || !edges.usable(node, to, eb) || slices.Contains(path, to) {
				return true
			}
			eb = eb.Intersect(edges.types)
			if routes.Refused(actor, node, to, eb) == eb {
				out.RefusedSteps++
				return true
			}
			next = append(next, candidate{to, eb.MaxProbability(node, to)})
			return true
		})
		slices.SortFunc(next, func(a, b candidate) int {
			return cmp.Or(cmp.Compare(b.probability, a.probability), cmp.Compare(a.node.Label(), b.node.Label()), cmp.Compare(a.node.ID(), b.node.ID()))
		})
		for _, c := range next {
			walk(c.node, actor, path, remaining-1)
		}
	}
	for length := shortest; length <= maxDepth && len(out.Routes) == 0 && !out.Limited; length++ {
		// A route of this length passes nodes up to one less from a target.
		for level < length-1 && len(frontier) > 0 {
			extend()
		}
		walk(source, nil, nil, length)
	}
	if err := ctx.Err(); err != nil {
		return nil, explainOutput{}, err
	}
	if len(out.Routes) > 0 {
		out.Reachable, out.Shortest = true, len(out.Routes[0].Steps)
	}
	if len(out.Routes) > limit {
		out.Routes, out.MoreRoutes = out.Routes[:limit], true
	}
	return nil, out, nil
}

func (s *Server) route(g *engine.IndexedGraph, path []*engine.Node, edges routeEdges, routes *engine.RouteChecker) Route {
	route := Route{}
	var actor *engine.Node
	for i, node := range path {
		route.Nodes = append(route.Nodes, s.Brief(node))
		if i > 0 {
			from := path[i-1]
			eb, _ := g.GetEdge(from, node)
			step := RouteStep{From: s.Brief(from), To: s.Brief(node), ActingAs: s.briefOf(actor)}
			step.EdgeTypes = s.edgeTypes(g, from, node, eb, edges.types, routes.Refused(actor, from, node, eb.Intersect(edges.types)))
			route.Steps = append(route.Steps, step)
		}
		if engine.IsActor(node) {
			actor = node
		}
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
