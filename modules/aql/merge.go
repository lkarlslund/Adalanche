package aql

import (
	"cmp"
	"encoding/binary"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
)

// A result can draw several nodes as one. Nodes merge when they have the
// same type and the same role in the query, and:
//
//   - MergeIdentical: the same edges, of the same types, to and from the
//     same nodes. Every route through one of them runs through all of them,
//     so nothing is lost.
//   - MergeRoutes: the same edges, of the same types, towards the query's
//     start nodes, to nodes that are themselves merged. They lead on to the
//     start in the same ways; their edges from the other side are combined,
//     so an edge into a merged node means it reaches at least one member.
//
// Thousands of users who reach a target through one common group become a
// single node.

// MergeMode is how a result merges nodes.
type MergeMode string

const (
	MergeOff       MergeMode = "off"
	MergeIdentical MergeMode = "identical"
	MergeRoutes    MergeMode = "routes"
)

func (m MergeMode) enabled() bool {
	return m == MergeIdentical || m == MergeRoutes
}

// keyedEdge is an edge between two nodes named by a numeric key.
type keyedEdge[K ~uint32] struct {
	from, to K
	edges    engine.EdgeBitmap
	flow     int
}

// mergeGroups returns, for each node, the lowest keyed node of its group.
// With side Any, nodes group by their exact edges on both sides. With side
// Out or In, they group by their edges on that side, to groups, until the
// groups no longer change.
func mergeGroups[K ~uint32](nodes []K, label func(K) string, edges []keyedEdge[K], side engine.EdgeDirection) map[K]K {
	type half struct {
		other K
		combo uint32
	}
	combos := map[engine.EdgeBitmap]uint32{}
	out, in := map[K][]half{}, map[K][]half{}
	for _, e := range edges {
		combo, found := combos[e.edges]
		if !found {
			combo = uint32(len(combos))
			combos[e.edges] = combo
		}
		out[e.from] = append(out[e.from], half{e.to, combo})
		in[e.to] = append(in[e.to], half{e.from, combo})
	}
	var sides []map[K][]half
	switch side {
	case engine.Out:
		sides = []map[K][]half{out}
	case engine.In:
		sides = []map[K][]half{in}
	default:
		sides = []map[K][]half{out, in}
	}
	compare := func(a, b half) int {
		return cmp.Or(cmp.Compare(a.other, b.other), cmp.Compare(a.combo, b.combo))
	}

	sorted := slices.Clone(nodes)
	slices.Sort(sorted)
	labels := make(map[K]string, len(sorted))
	group := make(map[K]K, len(sorted))
	for _, v := range sorted {
		labels[v] = label(v)
		group[v] = v
	}
	var key []byte
	var mapped []half
	for {
		first := map[string]K{}
		next := make(map[K]K, len(sorted))
		for _, v := range sorted {
			l := labels[v]
			key = binary.AppendUvarint(key[:0], uint64(len(l)))
			key = append(key, l...)
			for _, halves := range sides {
				mapped = mapped[:0]
				for _, h := range halves[v] {
					mapped = append(mapped, half{group[h.other], h.combo})
				}
				slices.SortFunc(mapped, compare)
				mapped = slices.Compact(mapped)
				key = binary.AppendUvarint(key, uint64(len(mapped)))
				for _, h := range mapped {
					key = binary.AppendUvarint(key, uint64(h.other))
					key = binary.AppendUvarint(key, uint64(h.combo))
				}
			}
			representative, found := first[string(key)]
			if !found {
				representative = v
				first[string(key)] = v
			}
			next[v] = representative
		}
		// Identical nodes take one pass: grouping again by groups would
		// merge nodes whose neighbours only look alike.
		if side == engine.Any || maps.Equal(next, group) {
			return next
		}
		group = next
	}
}

// mergeLabel is what besides its edges must match for two nodes to merge.
// Start nodes merge by routes only with themselves: they are what the
// query is about, and have no edges further towards the start to tell them
// apart by.
func mergeLabel(node *engine.Node, reference string, start bool) string {
	label := strconv.Itoa(int(node.Type())) + "\x00" + reference
	if start {
		label += "\x00" + strconv.FormatUint(uint64(node.ID()), 10)
	}
	return label
}

// startSide is the side of a node whose edges lead towards the query's start
// nodes: Out when every step runs towards the start (<-), In when every step
// runs away from it (->), Any otherwise.
func (aqlq AQLquery) startSide() engine.EdgeDirection {
	side := engine.Any
	for i, step := range aqlq.Next {
		var s engine.EdgeDirection
		switch step.Direction {
		case engine.In:
			s = engine.Out
		case engine.Out:
			s = engine.In
		default:
			return engine.Any
		}
		if i > 0 && s != side {
			return engine.Any
		}
		side = s
	}
	return side
}

// mergeSide is which edges nodes are compared by in a merge mode: both
// sides for identical nodes, the start side for routes. Routes fall back to
// identical nodes when the query has no single direction.
func mergeSide(mode MergeMode, startSide engine.EdgeDirection) engine.EdgeDirection {
	if mode == MergeRoutes {
		return startSide
	}
	return engine.Any
}

// MergedMember is one node drawn as part of a merged node.
type MergedMember struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// MergeNodes returns the graph with nodes merged as side says (see
// mergeGroups). A merged node keeps the data of its lowest numbered member,
// with "_merged" set to how many nodes it stands for and "_members" listing
// them. Edges between merged nodes combine their members' edge types and
// flows; edges between members of one merged node are left out.
func MergeNodes(g *graph.Graph[*engine.Node, engine.EdgeBitmap], side engine.EdgeDirection) *graph.Graph[*engine.Node, engine.EdgeBitmap] {
	byID := map[engine.NodeID]*engine.Node{}
	ids := make([]engine.NodeID, 0, g.Order())
	for node := range g.Nodes() {
		byID[node.ID()] = node
		ids = append(ids, node.ID())
	}
	var edges []keyedEdge[engine.NodeID]
	g.IterateEdges(func(source, target *engine.Node, eb engine.EdgeBitmap, flow int) bool {
		edges = append(edges, keyedEdge[engine.NodeID]{source.ID(), target.ID(), eb, flow})
		return true
	})
	reference := func(node *engine.Node) string {
		r, _ := g.GetNodeData(node, "reference").(string)
		return r
	}
	representatives := mergeGroups(ids, func(id engine.NodeID) string {
		node := byID[id]
		hop, hasHop := g.GetNodeData(node, "_hop").(int)
		return mergeLabel(node, reference(node), side != engine.Any && hasHop && hop == 0)
	}, edges, side)

	members := map[engine.NodeID][]MergedMember{}
	for _, id := range ids {
		r := representatives[id]
		members[r] = append(members[r], MergedMember{"n" + strconv.FormatUint(uint64(id), 10), byID[id].Label()})
	}
	merged := graph.NewGraphWithCapacity[*engine.Node, engine.EdgeBitmap](len(members), len(edges))
	for r, list := range members {
		node := byID[r]
		merged.AddNode(node)
		for key, value := range g.Nodes()[node] {
			merged.SetNodeData(node, key, value)
		}
		if len(list) > 1 {
			slices.SortFunc(list, func(a, b MergedMember) int { return cmp.Compare(a.Label, b.Label) })
			merged.SetNodeData(node, "_merged", len(list))
			merged.SetNodeData(node, "_members", list)
			// Folded contents of every member stay with the merged node.
			var contents []MergedMember
			for _, member := range list {
				id, _ := strconv.ParseUint(member.ID[1:], 10, 32)
				folded, _ := g.GetNodeData(byID[engine.NodeID(id)], "_folded").([]MergedMember)
				contents = append(contents, folded...)
			}
			if len(contents) > 0 {
				merged.SetNodeData(node, "_folded", contents)
			}
		}
	}
	for _, e := range edges {
		from, to := byID[representatives[e.from]], byID[representatives[e.to]]
		if from == to {
			continue
		}
		eb := e.edges
		if existing, found := merged.GetEdge(from, to); found {
			eb = existing.Merge(eb)
		}
		merged.AddEdgeFlow(from, to, eb, e.flow)
	}
	for _, reason := range g.Limits() {
		merged.Limited(reason)
	}
	return &merged
}

// Represented counts, by node type, the nodes a drawn node stands for: the
// node itself or the members merged into it, and the nodes folded into it,
// found by lookup.
func Represented(node *engine.Node, data map[string]any, lookup func(engine.NodeID) (*engine.Node, bool)) map[engine.NodeType]int {
	merged, _ := data["_merged"].(int)
	counts := map[engine.NodeType]int{node.Type(): max(merged, 1)}
	folded, _ := data["_folded"].([]MergedMember)
	for _, member := range folded {
		id, err := strconv.ParseUint(strings.TrimPrefix(member.ID, "n"), 10, 32)
		if err != nil {
			continue
		}
		if n, found := lookup(engine.NodeID(id)); found {
			counts[n.Type()]++
		}
	}
	return counts
}

// setHops records in "_hop" how many edges each node is from the query's
// start nodes, following routes back towards them.
func setHops(g *graph.Graph[*engine.Node, engine.EdgeBitmap], isStart func(*engine.Node) bool, startSide engine.EdgeDirection) {
	// towards lists, for each node, the nodes one edge further from the start.
	towards := map[*engine.Node][]*engine.Node{}
	g.IterateEdges(func(source, target *engine.Node, _ engine.EdgeBitmap, _ int) bool {
		if startSide != engine.In {
			towards[target] = append(towards[target], source)
		}
		if startSide != engine.Out {
			towards[source] = append(towards[source], target)
		}
		return true
	})
	hop := map[*engine.Node]int{}
	var frontier []*engine.Node
	for node := range g.Nodes() {
		if isStart(node) {
			hop[node] = 0
			frontier = append(frontier, node)
		}
	}
	for distance := 1; len(frontier) > 0; distance++ {
		var next []*engine.Node
		for _, node := range frontier {
			for _, other := range towards[node] {
				if _, found := hop[other]; !found {
					hop[other] = distance
					next = append(next, other)
				}
			}
		}
		frontier = next
	}
	for node, distance := range hop {
		g.SetNodeData(node, "_hop", distance)
	}
}

// FoldMachineLocal draws the nodes that belong to a machine in the result,
// its local groups and accounts, as part of the machine. Their edges become
// the machine's, and "_folded" lists them. Nodes a query step names are
// kept.
func FoldMachineLocal(g *graph.Graph[*engine.Node, engine.EdgeBitmap]) *graph.Graph[*engine.Node, engine.EdgeBitmap] {
	owner := map[*engine.Node]*engine.Node{}
	for node, data := range g.Nodes() {
		if reference, _ := data["reference"].(string); reference != "" {
			continue
		}
		if machine := node.Parent(); machine != nil && machine != node && machine.Type() == engine.NodeTypeMachine && g.HasNode(machine) {
			owner[node] = machine
		}
	}
	if len(owner) == 0 {
		return g
	}
	at := func(node *engine.Node) *engine.Node {
		if machine, found := owner[node]; found {
			return machine
		}
		return node
	}
	folded := graph.NewGraphWithCapacity[*engine.Node, engine.EdgeBitmap](g.Order()-len(owner), g.Size())
	contents := map[*engine.Node][]MergedMember{}
	for node, data := range g.Nodes() {
		if machine, found := owner[node]; found {
			contents[machine] = append(contents[machine], MergedMember{"n" + strconv.FormatUint(uint64(node.ID()), 10), node.Label()})
			continue
		}
		folded.AddNode(node)
		for key, value := range data {
			folded.SetNodeData(node, key, value)
		}
	}
	for machine, list := range contents {
		slices.SortFunc(list, func(a, b MergedMember) int { return cmp.Compare(a.Label, b.Label) })
		folded.SetNodeData(machine, "_folded", list)
	}
	g.IterateEdges(func(source, target *engine.Node, eb engine.EdgeBitmap, flow int) bool {
		from, to := at(source), at(target)
		if from == to {
			return true
		}
		if existing, found := folded.GetEdge(from, to); found {
			eb = existing.Merge(eb)
		}
		folded.AddEdgeFlow(from, to, eb, flow)
		return true
	})
	for _, reason := range g.Limits() {
		folded.Limited(reason)
	}
	return &folded
}
