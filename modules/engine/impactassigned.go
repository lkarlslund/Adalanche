package engine

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Seed each membership component with its directly controlled endpoints, then
// union these sets backwards through membership only. This computes M* C without
// expanding membership separately for every object or following a second C edge.
func (r *ImpactResult) calculateAssignedImpact(ctx context.Context, membership impactCSR, components []uint32, count int, capabilities impactCSR, options ImpactOptions) error {
	started := time.Now()
	dag, err := impactDAG(ctx, membership, components, count)
	if err != nil {
		return err
	}
	boundaries := make([]uint32, r.categories+1)
	for _, category := range r.targetClasses {
		if category >= 0 {
			boundaries[category+1]++
		}
	}
	for i := 1; i < len(boundaries); i++ {
		boundaries[i] += boundaries[i-1]
	}
	next := slices.Clone(boundaries)
	ids := make([]uint32, len(r.nodes))
	for i, category := range r.targetClasses {
		if category >= 0 {
			ids[i] = next[category]
			next[category]++
		}
	}
	seeds := impactCSR{offsets: make([]int, count+1)}
	for i := range r.nodes {
		if i&1023 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		for _, target := range capabilities.row(uint32(i)) {
			if r.targetClasses[target] >= 0 {
				seeds.offsets[components[i]+1]++
			}
		}
	}
	for i := 1; i < len(seeds.offsets); i++ {
		seeds.offsets[i] += seeds.offsets[i-1]
	}
	seeds.targets = make([]uint32, seeds.offsets[count])
	cursor := slices.Clone(seeds.offsets)
	for i := range r.nodes {
		if i&1023 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		for _, target := range capabilities.row(uint32(i)) {
			if r.targetClasses[target] >= 0 {
				component := components[i]
				seeds.targets[cursor[component]] = ids[target]
				cursor[component]++
			}
		}
	}
	counts := make([]uint32, count*r.categories)
	r.AssignedStatistics = ImpactStatistics{Nodes: len(r.nodes), Edges: len(dag.targets), Components: count,
		Targets: int(boundaries[len(boundaries)-1]), Workers: r.Statistics.Workers, PrepareTime: time.Since(started)}
	started = time.Now()
	bytes, shared, sets, err := propagateImpact(ctx, dag, dag.reverse(), seeds, boundaries, counts, options, r.Statistics.Workers)
	if err != nil {
		return err
	}
	r.assigned = make([]uint32, len(r.nodes)*r.categories)
	r.viaGroups = make([]uint32, len(r.nodes)*r.categories)
	var work atomic.Uint64
	var wg sync.WaitGroup
	for range min(r.Statistics.Workers, len(r.nodes)) {
		wg.Go(func() {
			builder := newImpactSetBuilder(boundaries[len(boundaries)-1])
			for {
				start := int(work.Add(256) - 256)
				if start >= len(r.nodes) || ctx.Err() != nil {
					return
				}
				for i := start; i < min(start+256, len(r.nodes)); i++ {
					category, component := r.targetClasses[i], components[i]
					row := r.assigned[i*r.categories : (i+1)*r.categories]
					copy(row, counts[int(component)*r.categories:int(component+1)*r.categories])
					if category >= 0 && sets[component].contains(ids[i]) {
						row[category]--
					}
					// Require a first membership hop, then reuse the already computed
					// assignment sets. One group needs no bitmap union or allocation.
					groups := membership.row(uint32(i))
					via := r.viaGroups[i*r.categories : (i+1)*r.categories]
					if len(groups) == 1 {
						group := components[groups[0]]
						copy(via, counts[int(group)*r.categories:int(group+1)*r.categories])
						if category >= 0 && sets[group].contains(ids[i]) {
							via[category]--
						}
					} else if len(groups) > 1 {
						for j, group := range groups {
							if j&1023 == 0 && ctx.Err() != nil {
								return
							}
							builder.union(sets[components[group]])
						}
						builder.measure(boundaries, via)
						if category >= 0 && builder.words[ids[i]/64]&(uint64(1)<<(ids[i]%64)) != 0 {
							via[category]--
						}
						builder.reset()
					}
				}
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	r.AssignedStatistics.SetBytes, r.AssignedStatistics.SharedSets = bytes, shared
	r.AssignedStatistics.PropagateTime = time.Since(started)
	return nil
}
