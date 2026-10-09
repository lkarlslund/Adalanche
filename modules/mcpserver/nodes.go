package mcpserver

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultLimit    = 25
	maxLimit        = 200
	maxAttrValues   = 20
	maxStringLength = 256
)

func clampLimit(limit, fallback, most int) int {
	if limit <= 0 {
		return fallback
	}
	return min(limit, most)
}

// NodeRef names a node.
type NodeRef struct {
	LocateBy string `json:"locate_by,omitempty" jsonschema:"how id names the node: nodeid or key (worked out from id when left out), dn, sid, guid, or an attribute name"`
	ID       any    `json:"id" jsonschema:"a node_id (123@k3f9) or key (objectSid=S-1-5-...) as tools give them, or a distinguished name, SID, GUID or attribute value"`
}

// text returns the id as given, whether as a number or a string.
func (r NodeRef) text() string {
	switch id := r.ID.(type) {
	case nil:
		return ""
	case float64:
		return strconv.FormatFloat(id, 'f', -1, 64)
	case string:
		return strings.TrimSpace(id)
	default:
		return strings.TrimSpace(fmt.Sprint(id))
	}
}

// Lookup finds the node a reference names.
func (s *Server) Lookup(g *engine.IndexedGraph, ref NodeRef) (*engine.Node, error) {
	id := ref.text()
	switch strings.ToLower(strings.TrimSpace(ref.LocateBy)) {
	case "":
		// A key holds "="; anything else is taken as a node id.
		if strings.Contains(id, "=") && !strings.Contains(id, "@") {
			return s.lookupKey(g, id)
		}
		fallthrough
	case "nodeid", "id", "node_id":
		nodeID, err := s.parseNodeID(id)
		if err != nil {
			return nil, err
		}
		if node, found := g.LookupNodeByID(nodeID); found {
			return node, nil
		}
		return nil, fmt.Errorf("node id %q not found", id)
	case "key":
		return s.lookupKey(g, id)
	case "dn", "distinguishedname":
		if node, found := g.Find(engine.DistinguishedName, engine.NV(id)); found {
			return node, nil
		}
		return nil, fmt.Errorf("distinguished name not found")
	case "sid", "objectsid":
		sid, err := windowssecurity.ParseStringSID(id)
		if err != nil {
			return nil, err
		}
		if node, found := g.Find(engine.ObjectSid, engine.NV(sid)); found {
			return node, nil
		}
		return nil, fmt.Errorf("SID not found")
	case "guid", "objectguid":
		guid, err := uuid.FromString(id)
		if err != nil {
			return nil, err
		}
		if node, found := g.Find(engine.ObjectGUID, engine.NV(guid)); found {
			return node, nil
		}
		return nil, fmt.Errorf("GUID not found")
	default:
		attr := engine.LookupAttribute(ref.LocateBy)
		if attr == engine.NonExistingAttribute {
			return nil, fmt.Errorf("unknown attribute %q", ref.LocateBy)
		}
		if secret(attr) {
			return nil, fmt.Errorf("attribute %q holds secrets and cannot be searched", ref.LocateBy)
		}
		if node, found := g.Find(attr, engine.NV(id)); found {
			return node, nil
		}
		return nil, fmt.Errorf("node not found")
	}
}

// NodeSummary describes a node with its attributes, secrets masked.
type NodeSummary struct {
	NodeBrief
	DistinguishedName string              `json:"distinguished_name,omitempty"`
	Attributes        map[string][]string `json:"attributes,omitempty"`
	Redacted          []string            `json:"redacted_attributes,omitempty"`
}

// Summary describes a node with the attributes selected, or all of them,
// leaving out hidden ones and masking secrets.
func (s *Server) Summary(node *engine.Node, selected []string) NodeSummary {
	summary := NodeSummary{
		NodeBrief:         s.Brief(node),
		DistinguishedName: sanitizeValue(node.DN()),
		Attributes:        map[string][]string{},
	}
	wanted := map[string]bool{}
	for _, name := range selected {
		wanted[strings.ToLower(name)] = true
	}
	node.AttrIterator(func(attr engine.Attribute, values engine.AttributeValues) bool {
		name := attr.String()
		if len(wanted) > 0 && !wanted[strings.ToLower(name)] {
			return true
		}
		if attr.HasFlag(engine.Hidden) {
			return true
		}
		if secret(attr) {
			summary.Attributes[name] = []string{redacted}
			summary.Redacted = append(summary.Redacted, name)
			return true
		}
		var list []string
		values.Iterate(func(value engine.AttributeValue) bool {
			list = append(list, sanitizeValue(value.String()))
			return len(list) < maxAttrValues
		})
		summary.Attributes[name] = list
		return true
	})
	slices.Sort(summary.Redacted)
	return summary
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

func (s *Server) addNodeTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "find_nodes",
		Description: "Find nodes matching an LDAP style filter, such as (&(type=Person)(name=adm*)) or (tag=hvt). Returns node ids for the other tools.",
	}, s.findNodes)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "get_node_details",
		Description: "Show one node with its attributes. Secrets are masked.",
	}, s.getNodeDetails)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "get_neighbors",
		Description: "List the edges of a node: outgoing (what it can do to others), incoming (who can do something to it) or both, with edge types and probabilities.",
	}, s.getNeighbors)
}

type findNodesInput struct {
	Filter     string   `json:"filter,omitempty" jsonschema:"LDAP style filter; empty matches every node"`
	Attributes []string `json:"attributes,omitempty" jsonschema:"attributes to include for each node; none gives names only"`
	OrderBy    string   `json:"order_by,omitempty" jsonschema:"attribute to sort by"`
	Descending bool     `json:"descending,omitempty" jsonschema:"sort descending"`
	Skip       int      `json:"skip,omitempty" jsonschema:"matching nodes to skip, for paging"`
	Limit      int      `json:"limit,omitempty" jsonschema:"nodes to return, at most 200 (default 25)"`
}

type findNodesOutput struct {
	Meta      Meta          `json:"meta"`
	Total     int           `json:"total"`
	Returned  int           `json:"returned"`
	Truncated bool          `json:"truncated"`
	Nodes     []NodeSummary `json:"nodes"`
}

func (s *Server) findNodes(_ context.Context, _ *mcp.CallToolRequest, in findNodesInput) (*mcp.CallToolResult, findNodesOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return nil, findNodesOutput{}, err
	}
	filter := strings.TrimSpace(in.Filter)
	if err := checkFilter(filter); err != nil {
		return nil, findNodesOutput{}, err
	}
	if in.OrderBy != "" && secretByName(in.OrderBy) {
		return nil, findNodesOutput{}, fmt.Errorf("attribute %q holds secrets and cannot be sorted by", in.OrderBy)
	}
	matches := g
	if filter != "" {
		selector, err := query.ParseLDAPQueryStrict(filter, g)
		if err != nil {
			return nil, findNodesOutput{}, err
		}
		matches = query.NodeFilterExecute(selector, g)
	}
	nodes := matches.AsSlice()
	total := nodes.Len()
	if in.OrderBy != "" {
		nodes.Sort(engine.LookupAttribute(in.OrderBy), in.Descending)
	}
	skip := max(in.Skip, 0)
	nodes.Skip(skip)
	nodes.Limit(clampLimit(in.Limit, defaultLimit, maxLimit))

	out := findNodesOutput{Meta: s.Meta(), Total: total, Returned: nodes.Len(), Truncated: total > skip+nodes.Len()}
	nodes.Iterate(func(n *engine.Node) bool {
		summary := NodeSummary{NodeBrief: s.Brief(n), DistinguishedName: sanitizeValue(n.DN())}
		if len(in.Attributes) > 0 {
			summary = s.Summary(n, in.Attributes)
		}
		out.Nodes = append(out.Nodes, summary)
		return true
	})
	return nil, out, nil
}

type nodeDetailsInput struct {
	NodeRef
	Attributes []string `json:"attributes,omitempty" jsonschema:"attributes to include; none gives all"`
}

type nodeDetailsOutput struct {
	Meta Meta        `json:"meta"`
	Node NodeSummary `json:"node"`
	// Parent is the node's container: an OU, or the machine of a local group.
	Parent   *NodeBrief `json:"parent,omitempty"`
	EdgesOut int        `json:"edges_out"`
	EdgesIn  int        `json:"edges_in"`
}

func (s *Server) getNodeDetails(_ context.Context, _ *mcp.CallToolRequest, in nodeDetailsInput) (*mcp.CallToolResult, nodeDetailsOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return nil, nodeDetailsOutput{}, err
	}
	node, err := s.Lookup(g, in.NodeRef)
	if err != nil {
		return nil, nodeDetailsOutput{}, err
	}
	out := nodeDetailsOutput{Meta: s.Meta(), Node: s.Summary(node, in.Attributes), Parent: s.briefOf(node.Parent())}
	g.IterateEdges(node, engine.Out, func(*engine.Node, engine.EdgeBitmap) bool { out.EdgesOut++; return true })
	g.IterateEdges(node, engine.In, func(*engine.Node, engine.EdgeBitmap) bool { out.EdgesIn++; return true })
	return nil, out, nil
}

type neighborsInput struct {
	NodeRef
	Direction string   `json:"direction,omitempty" jsonschema:"out (what the node can do to others), in (who can do something to it) or both (default)"`
	EdgeTypes []string `json:"edge_types,omitempty" jsonschema:"only edges with one of these types"`
	Skip      int      `json:"skip,omitempty" jsonschema:"edges to skip, for paging"`
	Limit     int      `json:"limit,omitempty" jsonschema:"edges to return, at most 200 (default 25)"`
}

// NeighborEdge is one edge between a node and a neighbor.
type NeighborEdge struct {
	Direction   string    `json:"direction"` // out: node to neighbor, in: neighbor to node
	Neighbor    NodeBrief `json:"neighbor"`
	EdgeTypes   []string  `json:"edge_types"`
	Probability int       `json:"probability"`
}

type neighborsOutput struct {
	Meta      Meta           `json:"meta"`
	Node      NodeBrief      `json:"node"`
	Total     int            `json:"total"`
	ByType    map[string]int `json:"neighbors_by_type"`
	Truncated bool           `json:"truncated"`
	Edges     []NeighborEdge `json:"edges"`
}

func edgeFilter(names []string) (engine.EdgeBitmap, error) {
	var bitmap engine.EdgeBitmap
	for _, name := range names {
		edge := engine.LookupEdge(name)
		if edge == engine.NonExistingEdge {
			return bitmap, fmt.Errorf("unknown edge type %q; list_schema lists them", name)
		}
		bitmap = bitmap.Set(edge)
	}
	return bitmap, nil
}

func (s *Server) getNeighbors(ctx context.Context, _ *mcp.CallToolRequest, in neighborsInput) (*mcp.CallToolResult, neighborsOutput, error) {
	g, err := s.Graph()
	if err != nil {
		return nil, neighborsOutput{}, err
	}
	node, err := s.Lookup(g, in.NodeRef)
	if err != nil {
		return nil, neighborsOutput{}, err
	}
	only, err := edgeFilter(in.EdgeTypes)
	if err != nil {
		return nil, neighborsOutput{}, err
	}
	var directions []engine.EdgeDirection
	switch strings.ToLower(in.Direction) {
	case "out":
		directions = []engine.EdgeDirection{engine.Out}
	case "in":
		directions = []engine.EdgeDirection{engine.In}
	case "", "both":
		directions = []engine.EdgeDirection{engine.Out, engine.In}
	default:
		return nil, neighborsOutput{}, fmt.Errorf("direction must be out, in or both")
	}

	out := neighborsOutput{Meta: s.Meta(), Node: s.Brief(node), ByType: map[string]int{}}
	var all []NeighborEdge
	for _, direction := range directions {
		g.IterateEdges(node, direction, func(other *engine.Node, eb engine.EdgeBitmap) bool {
			if !only.IsBlank() {
				eb = eb.Intersect(only)
				if eb.IsBlank() {
					return true
				}
			}
			from, to, name := node, other, "out"
			if direction == engine.In {
				from, to, name = other, node, "in"
			}
			all = append(all, NeighborEdge{name, s.Brief(other), eb.StringSlice(), int(eb.MaxProbability(from, to))})
			out.ByType[other.Type().Lookup()]++
			return !cancelled(ctx, len(all))
		})
	}
	if err := ctx.Err(); err != nil {
		return nil, neighborsOutput{}, err
	}
	slices.SortFunc(all, func(a, b NeighborEdge) int {
		return cmp.Or(cmp.Compare(a.Direction, b.Direction), cmp.Compare(b.Probability, a.Probability),
			cmp.Compare(a.Neighbor.Label, b.Neighbor.Label), cmp.Compare(a.Neighbor.NodeID, b.Neighbor.NodeID))
	})
	out.Total = len(all)
	skip := min(max(in.Skip, 0), len(all))
	end := min(skip+clampLimit(in.Limit, defaultLimit, maxLimit), len(all))
	out.Edges = all[skip:end]
	out.Truncated = end < len(all)
	return nil, out, nil
}
