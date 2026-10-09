package aql

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// REACH returns every edge on at least one valid route from a node matching
// the first node filter to a node matching the last one. A route may visit a
// node more than once; only the query's rules and the depth limit bound it.
//
// The search runs over states (node, step, depth within the step). Every
// transition moves to a later layer of (step, depth), so the states form a
// layered DAG: a forward pass finds the fewest edges from any start to each
// state, and a backward pass the fewest edges from each state to any end.
// A transition lies on a valid route exactly when the two distances plus the
// transition itself fit in the depth limit, because the shortest route to a
// state can always be joined with the shortest route on from it.

const reachUnreached = ^uint16(0)

// reachEdge is one edge a step may take from a node.
type reachEdge struct {
	target    engine.NodeIndex
	combo     engine.EdgeCombo // edges kept in the result
	direction engine.EdgeDirection
	lands     bool // target matches the next node filter
	continues bool // target may be passed through within the step
}

type reachSearch struct {
	aqlq      *AQLquery
	opts      ResolverOptions
	adjacency *engine.RankedAdjacency
	nodes     int
	maxDepth  int

	// Layers are numbered across steps: step i has one layer per depth
	// 0..max(MaxIterations,1)-1, and a final layer holds completed routes.
	layerStep  []int
	layerDepth []int
	stepLayer  []int // first layer of each step, plus the final layer

	forward, backward []uint16 // per layer*nodes+node
	active            [][]engine.NodeIndex
	edges             [][][]reachEdge // per step and node, nil until needed
	edgesDone         [][]bool
}

func (aqlq AQLquery) resolveReach(opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	if aqlq.OverAllProbability > 0 {
		return nil, errors.New("REACH does not support an accumulated probability limit")
	}
	s := reachSearch{
		aqlq:      &aqlq,
		opts:      opts,
		adjacency: aqlq.datasource.RankedAdjacency(),
		nodes:     aqlq.datasource.Order(),
		maxDepth:  opts.MaxDepth,
	}
	if s.maxDepth < 0 {
		s.maxDepth = 255 // the default the other modes use
	}
	s.maxDepth = min(s.maxDepth, int(reachUnreached)-1)
	if aqlq.Routes != RoutesAll && !s.recombinable() {
		return nil, errors.New("REACH CHEAPEST and SHORTEST need a query of one step in one direction, with no path node filter and at most one edge required")
	}

	for i, step := range aqlq.Next {
		s.stepLayer = append(s.stepLayer, len(s.layerStep))
		for d := range max(step.MaxIterations, 1) {
			s.layerStep = append(s.layerStep, i)
			s.layerDepth = append(s.layerDepth, d)
		}
	}
	s.stepLayer = append(s.stepLayer, len(s.layerStep))
	s.layerStep = append(s.layerStep, len(aqlq.Next))
	s.layerDepth = append(s.layerDepth, 0)

	layers := len(s.layerStep)
	s.forward = make([]uint16, layers*s.nodes)
	s.backward = make([]uint16, layers*s.nodes)
	for i := range s.forward {
		s.forward[i] = reachUnreached
		s.backward[i] = reachUnreached
	}
	s.active = make([][]engine.NodeIndex, layers)
	s.edges = make([][][]reachEdge, len(aqlq.Next))
	s.edgesDone = make([][]bool, len(aqlq.Next))
	for i := range aqlq.Next {
		s.edges[i] = make([][]reachEdge, s.nodes)
		s.edgesDone[i] = make([]bool, s.nodes)
	}

	pb := ui.ProgressBar("Searching routes", int64(2*layers))
	aqlq.sourceCache[0].Iterate(func(o *engine.Node) bool {
		if index, found := aqlq.datasource.NodeIndexOf(o); found {
			s.reachForward(0, index, 0)
		}
		return true
	})
	for layer := range layers - 1 {
		if err := opts.cancelled(); err != nil {
			pb.Finish()
			return nil, err
		}
		s.forwardLayer(layer)
		pb.Add(1)
	}
	for _, v := range s.active[layers-1] {
		s.backward[(layers-1)*s.nodes+int(v)] = 0
	}
	for layer := layers - 2; layer >= 0; layer-- {
		if err := opts.cancelled(); err != nil {
			pb.Finish()
			return nil, err
		}
		s.backwardLayer(layer)
		pb.Add(1)
	}
	pb.Finish()

	return s.result()
}

// reachForward records that a state is reachable with depth edges.
func (s *reachSearch) reachForward(layer int, v engine.NodeIndex, depth int) {
	state := layer*s.nodes + int(v)
	if s.forward[state] == reachUnreached {
		s.active[layer] = append(s.active[layer], v)
	}
	s.forward[state] = min(s.forward[state], uint16(depth))
}

// stepEdges returns the edges step may take from v, under all its rules.
func (s *reachSearch) stepEdges(step int, v engine.NodeIndex) []reachEdge {
	if s.edgesDone[step][v] {
		return s.edges[step][v]
	}
	s.edgesDone[step][v] = true
	es := s.aqlq.Next[step]
	ds := s.aqlq.datasource
	landing := s.aqlq.sourceCache[step+1]
	current := ds.NodeAt(v)

	var directions []engine.EdgeDirection
	switch es.Direction {
	case engine.In:
		directions = directionsIn
	case engine.Out:
		directions = directionsOut
	case engine.Any:
		directions = directionsAny
	}
	var result []reachEdge
	for _, direction := range directions {
		for _, e := range s.adjacency.Neighbors[direction][v] {
			next := ds.NodeAt(e.Target)
			kept, probability, ok := es.allows(s.opts, current, next, direction, ds.EdgeComboToEdgeBitmap(e.Combo))
			if !ok || probability < 0 {
				continue
			}
			re := reachEdge{
				target:    e.Target,
				combo:     ds.EdgeBitmapToEdgeCombo(kept),
				direction: direction,
				lands:     landing.Contains(next),
				continues: es.pathNodeRequirementCache == nil || es.pathNodeRequirementCache.Contains(next),
			}
			if re.lands || re.continues {
				result = append(result, re)
			}
		}
	}
	s.edges[step][v] = result
	return result
}

// transitions calls f for each state reachable from (layer, v) in one
// move: the layer and node it reaches, the edge taken, or nil for a step
// that takes no edges.
func (s *reachSearch) transitions(layer int, v engine.NodeIndex, f func(layer int, target engine.NodeIndex, edge *reachEdge)) {
	step, depth := s.layerStep[layer], s.layerDepth[layer]
	es := s.aqlq.Next[step]
	nextStep := s.stepLayer[step+1]

	// A step of zero edges stays on the node, which must match the next
	// node filter like any other landing.
	if depth == 0 && es.MinIterations == 0 && s.aqlq.sourceCache[step+1].Contains(s.aqlq.datasource.NodeAt(v)) {
		f(nextStep, v, nil)
	}
	if depth+1 > es.MaxIterations {
		return
	}
	edges := s.stepEdges(step, v)
	for i := range edges {
		e := &edges[i]
		if e.lands && depth+1 >= es.MinIterations {
			f(nextStep, e.target, e)
		}
		if e.continues && depth+1 < es.MaxIterations {
			f(layer+1, e.target, e)
		}
	}
}

func (s *reachSearch) forwardLayer(layer int) {
	for _, v := range s.active[layer] {
		depth := int(s.forward[layer*s.nodes+int(v)])
		s.transitions(layer, v, func(next int, target engine.NodeIndex, edge *reachEdge) {
			if edge == nil {
				s.reachForward(next, target, depth)
			} else if depth+1 <= s.maxDepth {
				s.reachForward(next, target, depth+1)
			}
		})
	}
}

func (s *reachSearch) backwardLayer(layer int) {
	for _, v := range s.active[layer] {
		best := reachUnreached
		s.transitions(layer, v, func(next int, target engine.NodeIndex, edge *reachEdge) {
			remaining := s.backward[next*s.nodes+int(target)]
			if remaining == reachUnreached {
				return
			}
			if edge != nil {
				remaining++
			}
			best = min(best, remaining)
		})
		s.backward[layer*s.nodes+int(v)] = best
	}
}

// routeLength is the length of the shortest route through a state, or
// reachUnreached when no route within the depth limit passes it.
func (s *reachSearch) routeLength(layer int, v engine.NodeIndex) int {
	state := layer*s.nodes + int(v)
	if s.backward[state] == reachUnreached {
		return int(reachUnreached)
	}
	return int(s.forward[state]) + int(s.backward[state])
}

// reachKey is an edge of a REACH result, in the edge's own direction.
type reachKey struct{ from, to engine.NodeIndex }

// reachResultEdge is the edge types on a REACH result edge, the length of
// the shortest route through it, and its flow (see countFlows).
type reachResultEdge struct {
	edges  engine.EdgeBitmap
	length int
	flow   int
}

func (s *reachSearch) result() (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	nodeLength := map[engine.NodeIndex]int{}
	reference := map[engine.NodeIndex]int{}
	edges := map[reachKey]reachResultEdge{}

	for layer := range s.layerStep {
		for _, v := range s.active[layer] {
			length := s.routeLength(layer, v)
			if length > s.maxDepth {
				continue
			}
			if l, found := nodeLength[v]; !found || length < l {
				nodeLength[v] = length
			}
			if s.layerDepth[layer] == 0 {
				// A node filter matched here; the last one in the query wins.
				reference[v] = max(reference[v], s.layerStep[layer]+1)
			}
			if layer == len(s.layerStep)-1 {
				continue
			}
			before := int(s.forward[layer*s.nodes+int(v)])
			s.transitions(layer, v, func(next int, target engine.NodeIndex, edge *reachEdge) {
				if edge == nil {
					return
				}
				after := s.backward[next*s.nodes+int(target)]
				if after == reachUnreached || before+1+int(after) > s.maxDepth {
					return
				}
				key := reachKey{v, target}
				if edge.direction == engine.In {
					key = reachKey{target, v}
				}
				re, found := edges[key]
				if !found {
					re.length = before + 1 + int(after)
					re.flow = 1
				}
				re.edges = re.edges.Merge(s.aqlq.datasource.EdgeComboToEdgeBitmap(edge.combo))
				re.length = min(re.length, before+1+int(after))
				edges[key] = re
			})
		}
	}

	var routesNote string
	if s.aqlq.Routes != RoutesAll {
		var err error
		if routesNote, err = s.pairRoutes(edges, nodeLength); err != nil {
			return nil, err
		}
	} else if err := s.countFlows(edges, nodeLength); err != nil {
		return nil, err
	}

	ds := s.aqlq.datasource
	referenceName := func(v engine.NodeIndex) string {
		if r, found := reference[v]; found {
			return s.aqlq.Sources[r-1].Reference
		}
		return ""
	}
	// drawn counts the nodes on routes of up to cutoff edges as they will be
	// drawn: folded and merged as the merge mode says.
	side := mergeSide(s.opts.MergeNodes, s.aqlq.startSide())
	drawn := func(cutoff int) int {
		var nodes []engine.NodeIndex
		for v, length := range nodeLength {
			if length <= cutoff {
				nodes = append(nodes, v)
			}
		}
		if !s.opts.MergeNodes.enabled() {
			return len(nodes)
		}
		// Routes mode folds machine-local nodes into their machine first,
		// as FoldMachineLocal does.
		at := func(v engine.NodeIndex) engine.NodeIndex { return v }
		if s.opts.MergeNodes == MergeRoutes {
			present := make(map[engine.NodeIndex]bool, len(nodes))
			for _, v := range nodes {
				present[v] = true
			}
			owner := map[engine.NodeIndex]engine.NodeIndex{}
			for _, v := range nodes {
				if referenceName(v) != "" {
					continue
				}
				machine := ds.NodeAt(v).Parent()
				if machine == nil || machine.Type() != engine.NodeTypeMachine {
					continue
				}
				if m, found := ds.NodeIndexOf(machine); found && m != v && present[m] {
					owner[v] = m
				}
			}
			nodes = slices.DeleteFunc(nodes, func(v engine.NodeIndex) bool {
				_, folded := owner[v]
				return folded
			})
			at = func(v engine.NodeIndex) engine.NodeIndex {
				if m, found := owner[v]; found {
					return m
				}
				return v
			}
		}
		var kept []keyedEdge[engine.NodeIndex]
		for key, re := range edges {
			if from, to := at(key.from), at(key.to); re.length <= cutoff && from != to {
				kept = append(kept, keyedEdge[engine.NodeIndex]{from, to, re.edges, 1})
			}
		}
		representatives := mergeGroups(nodes, func(v engine.NodeIndex) string {
			node := ds.NodeAt(v)
			return mergeLabel(node, referenceName(v), side != engine.Any && s.aqlq.sourceCache[0].Contains(node))
		}, kept, side)
		distinct := map[engine.NodeIndex]struct{}{}
		for _, r := range representatives {
			distinct[r] = struct{}{}
		}
		return len(distinct)
	}

	// Over the node limit, keep only the routes up to the longest length
	// that fits, so the result is still every route of those lengths.
	cutoff := s.maxDepth
	var limited string
	if s.opts.NodeLimit > 0 {
		if all := drawn(s.maxDepth); all > s.opts.NodeLimit {
			lengths := slices.Sorted(maps.Values(nodeLength))
			lengths = slices.Compact(lengths)
			kept := 0
			for _, length := range lengths {
				if err := s.opts.cancelled(); err != nil {
					return nil, err
				}
				count := drawn(length)
				if count > s.opts.NodeLimit {
					break
				}
				cutoff, kept = length, count
			}
			if kept == 0 {
				return nil, fmt.Errorf("REACH: the shortest routes alone have more than %v nodes", s.opts.NodeLimit)
			}
			limited = fmt.Sprintf("Node limit of %v reached: kept the %v nodes on routes of up to %v edges out of %v nodes on all routes", s.opts.NodeLimit, kept, cutoff, all)
			if s.opts.MergeNodes.enabled() {
				limited += " (counting merged nodes as one)"
			}
		}
	}

	result := graph.NewGraph[*engine.Node, engine.EdgeBitmap]()
	for v, length := range nodeLength {
		if length > cutoff {
			continue
		}
		node := ds.NodeAt(v)
		result.AddNode(node)
		if r, found := reference[v]; found && s.aqlq.Sources[r-1].Reference != "" {
			result.SetNodeData(node, "reference", s.aqlq.Sources[r-1].Reference)
		}
	}
	for key, re := range edges {
		if re.length <= cutoff {
			result.AddEdgeFlow(ds.NodeAt(key.from), ds.NodeAt(key.to), re.edges, re.flow)
		}
	}
	if limited != "" {
		result.Limited(limited)
	}
	if routesNote != "" {
		result.Limited(routesNote)
	}
	ui.Debug().Msgf("REACH found %v nodes and %v edges", result.Order(), result.Size())
	return &result, nil
}
