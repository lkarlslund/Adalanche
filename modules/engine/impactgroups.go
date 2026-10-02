package engine

import (
	"context"
	"slices"
	"time"
)

// Reuse the membership components for assigned impact and group exposure.
func (r *ImpactResult) calculateMembershipImpact(ctx context.Context, view *frozenGraph, capabilities impactCSR, options ImpactOptions) error {
	started := time.Now()
	membershipOptions := options
	membershipOptions.Edges = options.Edges.Intersect(options.GroupMembershipEdges)
	membership, err := impactAdjacency(ctx, view, membershipOptions)
	if err != nil {
		return err
	}
	// Membership must terminate at a group, regardless of imported edge labels.
	oldStart, write := 0, 0
	for i := range view.nodes {
		oldEnd := membership.offsets[i+1]
		membership.offsets[i] = write
		for _, target := range membership.targets[oldStart:oldEnd] {
			if view.nodes[target].Type() == NodeTypeGroup {
				membership.targets[write] = target
				write++
			}
		}
		oldStart = oldEnd
	}
	membership.offsets[len(view.nodes)] = write
	membership.targets = membership.targets[:write]
	components, count, err := impactComponents(ctx, membership)
	if err != nil {
		return err
	}
	membershipPrepare := time.Since(started)
	if err := r.calculateAssignedImpact(ctx, membership, components, count, capabilities, options); err != nil {
		return err
	}
	started = time.Now()
	memberIncoming := membership.reverse()
	if options.KeepConnections {
		for i := range view.nodes {
			slices.Sort(membership.row(uint32(i)))
			slices.Sort(memberIncoming.row(uint32(i)))
		}
		r.membershipIncoming, r.membershipOutgoing = memberIncoming, membership
	}
	if options.SourceClassify == nil {
		return nil
	}
	dag, err := impactDAG(ctx, memberIncoming, components, count)
	if err != nil {
		return err
	}
	options.Classify, options.Categories = options.SourceClassify, options.SourceCategories
	seeds, boundaries, classes, err := impactTargets(ctx, view.nodes, components, count, options)
	if err != nil {
		return err
	}
	counts := make([]uint32, count*options.Categories)
	r.GroupExposureStatistics = ImpactStatistics{Nodes: len(view.nodes), Edges: len(dag.targets), Components: count,
		Targets: len(seeds.targets), Workers: r.Statistics.Workers, PrepareTime: membershipPrepare + time.Since(started)}
	started = time.Now()
	bytes, shared, _, err := propagateImpact(ctx, dag, dag.reverse(), seeds, boundaries, counts, options, r.Statistics.Workers)
	if err != nil {
		return err
	}
	r.groupSources = make([]uint32, len(view.nodes)*options.Categories)
	for i, category := range classes {
		if i&1023 == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		start := int(components[i]) * options.Categories
		row := r.groupSources[i*options.Categories : (i+1)*options.Categories]
		copy(row, counts[start:start+options.Categories])
		if category >= 0 {
			row[category]--
		}
	}
	r.GroupExposureStatistics.SetBytes, r.GroupExposureStatistics.SharedSets = bytes, shared
	r.GroupExposureStatistics.PropagateTime = time.Since(started)
	return nil
}
