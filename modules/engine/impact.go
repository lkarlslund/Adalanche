package engine

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ImpactOptions selects a reachability policy, not a probability simulation.
type ImpactOptions struct {
	Edges               EdgeBitmap
	RequiredProbability Probability
	// Classify returns a category in [0, Categories), or -1 for a transit node.
	// Each counted node is one distinct target. Its own impact includes itself.
	Classify   func(*Node) int
	Categories int
	// SourceClassify enables upstream counts, using independently classified sources.
	SourceClassify   func(*Node) int
	SourceCategories int
	// GroupMembershipEdges permits membership hops before the first capability
	// when calculating assigned impact, and enables membership-only exposure.
	GroupMembershipEdges EdgeBitmap
	// KeepConnections retains compact adjacency for on-demand contributor inspection.
	KeepConnections bool
	// Workers defaults to GOMAXPROCS. Only independent components run concurrently.
	Workers int
	// MaxSetBytes limits retained set payloads, not total process memory. Zero is unlimited.
	MaxSetBytes uint64
}

type ImpactStatistics struct {
	Nodes, Edges, Components, Targets, Workers int
	SetBytes                                   uint64
	SharedSets                                 uint64
	PrepareTime, PropagateTime                 time.Duration
}

// ImpactResult retains counts and node-to-component indexes, but no target sets.
type ImpactResult struct {
	edges, membershipEdges           EdgeBitmap
	requiredProbability              Probability
	graph                            *IndexedGraph
	nodes                            []*Node
	component                        []uint32
	counts                           []uint32
	categories                       int
	Statistics                       ImpactStatistics
	ExposureStatistics               ImpactStatistics
	GroupExposureStatistics          ImpactStatistics
	AssignedStatistics               ImpactStatistics
	assigned                         []uint32
	viaGroups                        []uint32
	membershipOutgoing, capabilities impactCSR
	groupSources                     []uint32
	membershipIncoming               impactCSR
	direct                           []uint32
	sources                          []uint32
	sourceCategories                 int
	targetClasses, sourceClasses     []int16
	outgoing, incoming               impactCSR
}

// Counts returns a read-only category-count slice, or nil for a node outside this graph.
func (r *ImpactResult) Counts(node *Node) []uint32 {
	if node == nil || r.graph == nil {
		return nil
	}
	index, found := r.graph.nodeToIndex(node)
	if !found || uint64(index) >= uint64(len(r.nodes)) || r.nodes[index] != node {
		return nil
	}
	start := int(r.component[index]) * r.categories
	return r.counts[start : start+r.categories]
}

// IterateParallel visits exactly the analyzed snapshot's nodes with their counts.
// Count slices are shared between component members and must be treated as read-only.
// Callbacks may publish attributes, but must not mutate topology or counts.
func (r *ImpactResult) IterateParallel(each func(*Node, []uint32)) {
	r.IterateMetricsParallel(func(node *Node, metrics ImpactMetrics) { each(node, metrics.Total) })
}

// ImpactMetrics contains read-only counts. Indirect excludes self and direct
// neighbours even when a longer path to the same target also exists.
type ImpactMetrics struct {
	Total, Direct, Sources []uint32
	SourceCategory         int
	TargetCategory         int
	GroupSources           []uint32
	Assigned               []uint32
	// ViaGroups requires at least one membership hop before one capability.
	// It can overlap Direct; Assigned is their distinct union. All exclude self.
	ViaGroups []uint32
}

// TotalImpact excludes the starting object from reflexive reachability counts.
func (m ImpactMetrics) TotalImpact(category int) uint32 {
	count := m.Total[category]
	if category == m.TargetCategory {
		count--
	}
	return count
}

// Consequential excludes targets already controlled through existing assignments.
func (m ImpactMetrics) Consequential(category int) uint32 {
	return m.TotalImpact(category) - m.Assigned[category]
}

// DirectImpact counts directly connected endpoints, excluding the object itself.
func (m ImpactMetrics) DirectImpact(category int) uint32 {
	count := m.Direct[category]
	if category == m.TargetCategory {
		count--
	}
	return count
}

func (m ImpactMetrics) Indirect(category int) uint32 {
	return m.Total[category] - m.Direct[category]
}

// Exposure excludes the inspected object itself from its upstream sources.
func (m ImpactMetrics) Exposure(category int) uint32 {
	count := m.Sources[category]
	if category == m.SourceCategory {
		count--
	}
	return count
}

// OtherExposure excludes sources that also have a qualifying membership route.
func (m ImpactMetrics) OtherExposure(category int) uint32 {
	return m.Exposure(category) - m.GroupSources[category]
}

// IterateMetricsParallel visits the snapshot without per-node lookup or allocation.
func (r *ImpactResult) IterateMetricsParallel(each func(*Node, ImpactMetrics)) {
	var next atomic.Uint64
	var wg sync.WaitGroup
	for range min(r.Statistics.Workers, len(r.nodes)) {
		wg.Go(func() {
			for {
				start := int(next.Add(256) - 256)
				if start >= len(r.nodes) {
					return
				}
				for i := start; i < min(start+256, len(r.nodes)); i++ {
					position := int(r.component[i]) * r.categories
					metrics := ImpactMetrics{Total: r.counts[position : position+r.categories],
						Direct: r.direct[i*r.categories : (i+1)*r.categories], SourceCategory: -1, TargetCategory: int(r.targetClasses[i])}
					metrics.Assigned = r.assigned[i*r.categories : (i+1)*r.categories]
					metrics.ViaGroups = r.viaGroups[i*r.categories : (i+1)*r.categories]
					if r.sourceCategories != 0 {
						start := int(r.component[i]) * r.sourceCategories
						metrics.Sources = r.sources[start : start+r.sourceCategories]
						metrics.SourceCategory = int(r.sourceClasses[i])
						if r.groupSources != nil {
							metrics.GroupSources = r.groupSources[i*r.sourceCategories : (i+1)*r.sourceCategories]
						}
					}
					each(r.nodes[i], metrics)
				}
			}
		})
	}
	wg.Wait()
}

// CalculateImpact computes exact reflexive reachability using immutable adaptive
// target sets on the component DAG. It trades temporary RAM for one backwards
// propagation, without traversing the graph separately for every starting node.
// The graph and probability/classification inputs must not change during the call.
// Cancellation or a set-budget failure returns no result and modifies no nodes.
func CalculateImpact(ctx context.Context, view *FrozenGraph, options ImpactOptions) (*ImpactResult, error) {
	if view == nil || options.Classify == nil || options.Categories < 1 || options.Categories > 256 || options.Workers < 0 {
		return nil, errors.New("invalid impact options")
	}
	if options.RequiredProbability < 1 || options.RequiredProbability > 100 {
		return nil, errors.New("impact probability threshold must be between 1 and 100")
	}
	if (options.SourceClassify == nil) != (options.SourceCategories == 0) || options.SourceCategories < 0 || options.SourceCategories > 256 {
		return nil, errors.New("invalid impact source categories")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	started := time.Now()
	adjacency, err := impactAdjacency(ctx, view, options)
	if err != nil {
		return nil, err
	}
	component, componentCount, err := impactComponents(ctx, adjacency)
	if err != nil {
		return nil, err
	}
	dag, err := impactDAG(ctx, adjacency, component, componentCount)
	if err != nil {
		return nil, err
	}
	parents := dag.reverse()
	seeds, boundaries, classes, err := impactTargets(ctx, view.nodes, component, componentCount, options)
	if err != nil {
		return nil, err
	}
	workers := options.Workers
	if workers == 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	workers = max(1, min(workers, componentCount))
	result := &ImpactResult{
		edges: options.Edges, membershipEdges: options.GroupMembershipEdges, requiredProbability: options.RequiredProbability,
		graph: view.graph, nodes: view.nodes, component: component, categories: options.Categories,
		counts: make([]uint32, componentCount*options.Categories),
		Statistics: ImpactStatistics{Nodes: len(view.nodes), Edges: len(adjacency.targets), Components: componentCount,
			Targets: len(seeds.targets), Workers: workers, PrepareTime: time.Since(started)},
	}
	started = time.Now()
	setBytes, shared, _, err := propagateImpact(ctx, dag, parents, seeds, boundaries, result.counts, options, workers)
	if err != nil {
		return nil, err
	}
	result.Statistics.SetBytes = setBytes
	result.Statistics.SharedSets = shared
	result.Statistics.PropagateTime = time.Since(started)
	result.targetClasses = classes
	capabilities := adjacency
	if !options.GroupMembershipEdges.IsBlank() {
		capabilityOptions := options
		for _, edge := range options.GroupMembershipEdges.Edges() {
			capabilityOptions.Edges = capabilityOptions.Edges.Clear(edge)
		}
		capabilities, err = impactAdjacency(ctx, view, capabilityOptions)
		if err != nil {
			return nil, err
		}
	}
	result.direct = make([]uint32, len(view.nodes)*options.Categories)
	for i, category := range classes {
		if i&1023 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		counts := result.direct[i*options.Categories : (i+1)*options.Categories]
		if category >= 0 {
			counts[category]++
		}
		for _, target := range capabilities.row(uint32(i)) {
			if int(target) != i && classes[target] >= 0 {
				counts[classes[target]]++
			}
		}
	}
	if options.SourceClassify != nil {
		started = time.Now()
		sourceOptions := options
		sourceOptions.Classify, sourceOptions.Categories = options.SourceClassify, options.SourceCategories
		sourceSeeds, sourceBoundaries, sourceClasses, err := impactTargets(ctx, view.nodes, component, componentCount, sourceOptions)
		if err != nil {
			return nil, err
		}
		result.sourceCategories, result.sourceClasses = options.SourceCategories, sourceClasses
		result.sources = make([]uint32, componentCount*options.SourceCategories)
		result.ExposureStatistics = ImpactStatistics{Nodes: len(view.nodes), Edges: len(adjacency.targets), Components: componentCount,
			Targets: len(sourceSeeds.targets), Workers: workers, PrepareTime: time.Since(started)}
		started = time.Now()
		// Reverse the same condensed graph. Downstream sets have already been released;
		// the payload budget applies independently to each propagation pass.
		setBytes, shared, _, err := propagateImpact(ctx, parents, dag, sourceSeeds, sourceBoundaries, result.sources, sourceOptions, workers)
		if err != nil {
			return nil, err
		}
		result.ExposureStatistics.SetBytes, result.ExposureStatistics.SharedSets = setBytes, shared
		result.ExposureStatistics.PropagateTime = time.Since(started)
	}
	if !options.GroupMembershipEdges.IsBlank() {
		if err := result.calculateMembershipImpact(ctx, view, capabilities, options); err != nil {
			return nil, err
		}
	} else {
		result.assigned = slices.Clone(result.direct)
		result.viaGroups = make([]uint32, len(view.nodes)*options.Categories)
		for i, category := range classes {
			if category >= 0 {
				result.assigned[i*options.Categories+int(category)]--
			}
		}
	}
	if options.KeepConnections {
		for i := range view.nodes {
			slices.Sort(adjacency.row(uint32(i)))
		}
		result.outgoing, result.incoming = adjacency, adjacency.reverse()
		result.capabilities = capabilities
		for i := range view.nodes {
			slices.Sort(result.capabilities.row(uint32(i)))
		}
	}
	return result, nil
}

type impactCSR struct {
	offsets []int
	targets []uint32
}

func (g impactCSR) row(node uint32) []uint32 {
	return g.targets[g.offsets[node]:g.offsets[int(node)+1]]
}

func (g impactCSR) reverse() impactCSR {
	r := impactCSR{offsets: make([]int, len(g.offsets)), targets: make([]uint32, len(g.targets))}
	for _, target := range g.targets {
		r.offsets[int(target)+1]++
	}
	for i := 1; i < len(r.offsets); i++ {
		r.offsets[i] += r.offsets[i-1]
	}
	cursor := slices.Clone(r.offsets)
	for source := 0; source+1 < len(g.offsets); source++ {
		for _, target := range g.row(uint32(source)) {
			r.targets[cursor[target]] = uint32(source)
			cursor[target]++
		}
	}
	return r
}

func impactAdjacency(ctx context.Context, view *FrozenGraph, options ImpactOptions) (impactCSR, error) {
	g := impactCSR{offsets: make([]int, len(view.nodes)+1)}
	capacity := 0
	for _, row := range view.edges[Out] {
		capacity += len(row)
	}
	g.targets = make([]uint32, 0, capacity)
	var certain, dynamic EdgeBitmap
	for edge, info := range edgeInfos {
		if !options.Edges.IsSet(Edge(edge)) {
			continue
		}
		if info.probability == nil {
			certain = certain.set(Edge(edge))
		} else if info.fixedProbability != nil {
			if *info.fixedProbability >= options.RequiredProbability {
				certain = certain.set(Edge(edge))
			}
		} else {
			dynamic = dynamic.set(Edge(edge))
		}
	}
	for i, source := range view.nodes {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return impactCSR{}, err
			}
		}
		for j := range view.edges[Out][i] {
			connection := &view.edges[Out][i][j]
			if !connection.edge.Intersect(certain).IsBlank() {
				g.targets = append(g.targets, uint32(connection.target))
				continue
			}
			eligible := connection.edge.Intersect(dynamic)
			if eligible.IsBlank() {
				continue
			}
			// Pass the complete edge bitmap to calculators: some inspect companion rights.
			allEdges := connection.edge
			accepted := false
			for wordIndex, word := range eligible {
				for word != 0 {
					edge := Edge(wordIndex*64 + bits.TrailingZeros64(word))
					if edge.Probability(source, view.nodes[connection.target], &allEdges) >= options.RequiredProbability {
						accepted = true
						break
					}
					word &= word - 1
				}
				if accepted {
					break
				}
			}
			if accepted {
				g.targets = append(g.targets, uint32(connection.target))
			}
		}
		g.offsets[i+1] = len(g.targets)
	}
	// Narrow policies such as membership must not retain capacity for every edge.
	if len(g.targets) == 0 {
		g.targets = nil
	} else if len(g.targets) < cap(g.targets)/2 {
		g.targets = slices.Clone(g.targets)
	}
	return g, nil
}

// Iterative Kosaraju avoids recursion proportional to a long attack chain.
func impactComponents(ctx context.Context, g impactCSR) ([]uint32, int, error) {
	n := len(g.offsets) - 1
	visited := make([]bool, n)
	order := make([]uint32, 0, n)
	type frame struct{ node, next uint32 }
	stack := make([]frame, 0)
	for root := range n {
		if visited[root] {
			continue
		}
		visited[root] = true
		stack = append(stack, frame{node: uint32(root)})
		for len(stack) != 0 {
			if (len(order)+len(stack))&1023 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, 0, err
				}
			}
			last := &stack[len(stack)-1]
			neighbours := g.row(last.node)
			if int(last.next) == len(neighbours) {
				order = append(order, last.node)
				stack = stack[:len(stack)-1]
				continue
			}
			target := neighbours[last.next]
			last.next++
			if !visited[target] {
				visited[target] = true
				stack = append(stack, frame{node: target})
			}
		}
	}
	reversed := g.reverse()
	clear(visited)
	component := make([]uint32, n)
	pending := make([]uint32, 0)
	count := 0
	for i := len(order) - 1; i >= 0; i-- {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
		}
		root := order[i]
		if visited[root] {
			continue
		}
		visited[root] = true
		pending = append(pending, root)
		for len(pending) != 0 {
			node := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			component[node] = uint32(count)
			for _, target := range reversed.row(node) {
				if !visited[target] {
					visited[target] = true
					pending = append(pending, target)
				}
			}
		}
		count++
	}
	return component, count, nil
}

func impactDAG(ctx context.Context, g impactCSR, component []uint32, count int) (impactCSR, error) {
	dag := impactCSR{offsets: make([]int, count+1)}
	for source, from := range component {
		for _, target := range g.row(uint32(source)) {
			if from != component[target] {
				dag.offsets[int(from)+1]++
			}
		}
	}
	for i := 1; i < len(dag.offsets); i++ {
		dag.offsets[i] += dag.offsets[i-1]
	}
	dag.targets = make([]uint32, dag.offsets[count])
	cursor := slices.Clone(dag.offsets)
	for source, from := range component {
		for _, target := range g.row(uint32(source)) {
			if to := component[target]; from != to {
				dag.targets[cursor[from]] = to
				cursor[from]++
			}
		}
	}
	// Deduplicate component edges in place, without per-component maps.
	oldStart, write := 0, 0
	for i := range count {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return impactCSR{}, err
			}
		}
		oldEnd := dag.offsets[i+1]
		row := dag.targets[oldStart:oldEnd]
		slices.Sort(row)
		row = slices.Compact(row)
		dag.offsets[i] = write
		write += copy(dag.targets[write:], row)
		oldStart = oldEnd
	}
	dag.offsets[count] = write
	dag.targets = dag.targets[:write]
	return dag, nil
}

func impactTargets(ctx context.Context, nodes []*Node, component []uint32, count int, options ImpactOptions) (impactCSR, []uint32, []int16, error) {
	classes := make([]int16, len(nodes))
	boundaries := make([]uint32, options.Categories+1)
	seeds := impactCSR{offsets: make([]int, count+1)}
	for i, node := range nodes {
		if i&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return impactCSR{}, nil, nil, err
			}
		}
		category := options.Classify(node)
		if category < -1 || category >= options.Categories {
			return impactCSR{}, nil, nil, fmt.Errorf("impact category %d is outside the configured range", category)
		}
		classes[i] = int16(category)
		if category >= 0 {
			boundaries[category+1]++
			seeds.offsets[int(component[i])+1]++
		}
	}
	for i := 1; i < len(boundaries); i++ {
		boundaries[i] += boundaries[i-1]
	}
	for i := 1; i < len(seeds.offsets); i++ {
		seeds.offsets[i] += seeds.offsets[i-1]
	}
	seeds.targets = make([]uint32, seeds.offsets[count])
	nextID := slices.Clone(boundaries)
	cursor := slices.Clone(seeds.offsets)
	for i, category := range classes {
		if category >= 0 {
			c := component[i]
			seeds.targets[cursor[c]] = nextID[category]
			cursor[c]++
			nextID[category]++
		}
	}
	return seeds, boundaries, classes, nil
}

func propagateImpact(ctx context.Context, dag, parents, seeds impactCSR, boundaries []uint32, counts []uint32, options ImpactOptions, workers int) (uint64, uint64, []impactSet, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	n := len(dag.offsets) - 1
	if n == 0 {
		return 0, 0, nil, ctx.Err()
	}
	sets := make([]impactSet, n)
	dependencies := make([]atomic.Uint32, n)
	ready := make(chan uint32, n)
	for i := range n {
		degree := len(dag.row(uint32(i)))
		dependencies[i].Store(uint32(degree))
		if degree == 0 {
			ready <- uint32(i)
		}
	}
	var remaining atomic.Int64
	remaining.Store(int64(n))
	var allocated, shared atomic.Uint64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			builder := newImpactSetBuilder(boundaries[len(boundaries)-1])
			for {
				select {
				case <-ctx.Done():
					return
				case c, ok := <-ready:
					if !ok || ctx.Err() != nil {
						return
					}
					for {
						if ctx.Err() != nil {
							return
						}
						children, own := dag.row(c), seeds.row(c)
						var set impactSet
						if len(children) == 1 && len(own) == 0 {
							set = sets[children[0]] // Immutable: no copying down chains or fan-in.
							shared.Add(1)
							copy(counts[int(c)*options.Categories:], counts[int(children[0])*options.Categories:int(children[0]+1)*options.Categories])
						} else {
							var largest impactSet
							for i, child := range children {
								if i&1023 == 0 && ctx.Err() != nil {
									return
								}
								builder.union(sets[child])
								if sets[child].count > largest.count {
									largest = sets[child]
								}
							}
							for _, target := range own {
								builder.addWord(target/64, uint64(1)<<(target%64))
							}
							var err error
							set, err = builder.finish(largest, boundaries, counts[int(c)*options.Categories:int(c+1)*options.Categories], &allocated, options.MaxSetBytes)
							if err != nil {
								cancel(err)
								return
							}
							if set.count != 0 && set.count == largest.count {
								shared.Add(1)
							}
						}
						sets[c] = set
						// Publish before decrementing dependencies. The final predecessor
						// notification makes all immutable successor sets available to its worker.
						var next uint32
						hasNext := false
						for _, parent := range parents.row(c) {
							if dependencies[parent].Add(^uint32(0)) == 0 {
								if !hasNext {
									next, hasNext = parent, true
								} else {
									ready <- parent
								}
							}
						}
						if remaining.Add(-1) == 0 {
							close(ready)
							return
						}
						if !hasNext {
							break
						}
						c = next
					}
				}
			}
		})
	}
	wg.Wait()
	return allocated.Load(), shared.Load(), sets, context.Cause(ctx)
}
