package engine

import (
	"context"
	"errors"
	"slices"
	"strconv"
)

type ImpactDirection string

const (
	ImpactDownstream        ImpactDirection = "impact"
	ImpactDirect            ImpactDirection = "direct"
	ImpactAssigned          ImpactDirection = "assigned"
	ImpactViaGroups         ImpactDirection = "impact-groups"
	ImpactConsequential     ImpactDirection = "consequential"
	ImpactIndirect          ImpactDirection = "indirect"
	ImpactUpstream          ImpactDirection = "exposure"
	ImpactExposureViaGroups ImpactDirection = "exposure-groups"
	ImpactExposureOther     ImpactDirection = "exposure-other"
)

type ImpactContributor struct {
	Node *Node
	// Path follows capability direction; at most 128 nodes, starting at the source.
	Path []*Node
	// PathEdges[i] contains eligible capabilities from Path[i] to Path[i+1].
	PathEdges     []EdgeBitmap
	Hops          int
	PathTruncated bool
}

type ImpactPage struct {
	Total int
	Items []ImpactContributor
}

// Inspect lists distinct contributors in snapshot order with a shortest example
// path. It uses O(nodes) temporary memory, not a retained all-pairs path index.
// Category -1 selects all classified categories. Callers should bound concurrency.
func (r *ImpactResult) Inspect(ctx context.Context, node *Node, direction ImpactDirection, category, offset, limit int) (ImpactPage, error) {
	if err := ctx.Err(); err != nil {
		return ImpactPage{}, err
	}
	if len(r.outgoing.offsets) == 0 {
		return ImpactPage{}, errors.New("impact connections were not retained")
	}
	if offset < 0 || limit < 1 || limit > 100 {
		return ImpactPage{}, errors.New("invalid impact page")
	}
	adjacency, classes, categories := r.outgoing, r.targetClasses, r.categories
	switch direction {
	case ImpactDownstream, ImpactDirect, ImpactAssigned, ImpactViaGroups, ImpactConsequential, ImpactIndirect:
	case ImpactUpstream, ImpactExposureViaGroups, ImpactExposureOther:
		adjacency, classes, categories = r.incoming, r.sourceClasses, r.sourceCategories
	default:
		return ImpactPage{}, errors.New("invalid impact direction")
	}
	if categories == 0 || category < -1 || category >= categories {
		return ImpactPage{}, errors.New("invalid impact category")
	}
	if node == nil || r.graph == nil {
		return ImpactPage{}, errors.New("node outside impact snapshot")
	}
	index, found := r.graph.nodeToIndex(node)
	if !found || uint64(index) >= uint64(len(r.nodes)) || r.nodes[index] != node {
		return ImpactPage{}, errors.New("node outside impact snapshot")
	}
	root := uint32(index)
	upstream := direction == ImpactUpstream || direction == ImpactExposureViaGroups || direction == ImpactExposureOther
	partitioned := direction == ImpactExposureViaGroups || direction == ImpactExposureOther
	if partitioned && r.groupSources == nil {
		return ImpactPage{}, errors.New("group exposure was not calculated")
	}
	const unseen = ^uint32(0)
	previous := make([]uint32, len(r.nodes))
	for i := range previous {
		previous[i] = unseen
	}
	queue := make([]uint32, 0, len(r.nodes))
	if direction == ImpactDirect {
		adjacency = r.capabilities
	}
	walk := func(groupsOnly bool) error {
		previous[root] = root
		queue = append(queue[:0], root)
		for head := 0; head < len(queue); head++ {
			if head&1023 == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			current := queue[head]
			if direction == ImpactDirect && current != root {
				continue
			}
			neighbours := adjacency.row(current)
			if groupsOnly {
				neighbours = r.membershipIncoming.row(current)
			}
			for j, target := range neighbours {
				if j&4095 == 0 && ctx.Err() != nil {
					return ctx.Err()
				}
				if previous[target] == unseen {
					previous[target] = current
					queue = append(queue, target)
				}
			}
		}
		return nil
	}
	var membershipPrevious, assignedVia []uint32
	assignmentPath := direction == ImpactAssigned || direction == ImpactViaGroups
	if assignmentPath || direction == ImpactConsequential {
		var err error
		membershipPrevious, assignedVia, err = r.assignedPredecessors(ctx, root, direction == ImpactViaGroups)
		if err != nil {
			return ImpactPage{}, err
		}
	}
	if assignmentPath {
		previous = assignedVia
	} else {
		if err := walk(partitioned); err != nil {
			return ImpactPage{}, err
		}
	}
	var viaGroups []bool
	if direction == ImpactExposureOther {
		viaGroups = make([]bool, len(r.nodes))
		for i, predecessor := range previous {
			viaGroups[i] = predecessor != unseen
			previous[i] = unseen
		}
		if err := walk(false); err != nil {
			return ImpactPage{}, err
		}
	}
	page := ImpactPage{Items: make([]ImpactContributor, 0, limit)}
	for i, class := range classes {
		if i&1023 == 0 && ctx.Err() != nil {
			return ImpactPage{}, ctx.Err()
		}
		if class < 0 || (category >= 0 && int(class) != category) || previous[i] == unseen {
			continue
		}
		if uint32(i) == root {
			continue
		}
		if direction == ImpactConsequential && assignedVia[i] != unseen {
			continue
		}
		if viaGroups != nil && viaGroups[i] {
			continue
		}
		if direction == ImpactIndirect {
			if _, direct := slices.BinarySearch(r.capabilities.row(root), uint32(i)); direct {
				continue
			}
		}
		if direction == ImpactDirect && uint32(i) == root {
			continue
		}
		page.Total++
		if page.Total <= offset || len(page.Items) == limit {
			continue
		}
		item := ImpactContributor{Node: r.nodes[i]}
		current := uint32(i)
		// Count the entire path, retaining only a bounded portion. For downstream
		// paths keep the source end, so a truncated path never implies a false jump.
		var tail [128]*Node
		length := 0
		for {
			if length&1023 == 0 && ctx.Err() != nil {
				return ImpactPage{}, ctx.Err()
			}
			if upstream {
				if length < len(tail) {
					tail[length] = r.nodes[current]
				}
			} else {
				tail[length%len(tail)] = r.nodes[current]
			}
			length++
			// A group cycle can return to the source before the final capability.
			// For Via groups that first return still needs a membership witness.
			if current == root && !(direction == ImpactViaGroups && length == 2) {
				break
			}
			if assignmentPath && length > 1 {
				current = membershipPrevious[current]
			} else {
				current = previous[current]
			}
		}
		item.Hops, item.PathTruncated = length-1, length > len(tail)
		item.Path = make([]*Node, min(length, len(tail)))
		if upstream {
			copy(item.Path, tail[:])
		} else {
			for j := range item.Path {
				item.Path[j] = tail[(length-1-j)%len(tail)]
			}
		}
		item.PathEdges = make([]EdgeBitmap, len(item.Path)-1)
		for hop := range item.PathEdges {
			if err := ctx.Err(); err != nil {
				return ImpactPage{}, err
			}
			source, target := item.Path[hop], item.Path[hop+1]
			all, _ := r.graph.GetEdge(source, target)
			eligible := all.Intersect(r.edges)
			membershipOnly := direction == ImpactExposureViaGroups || (assignmentPath && hop < item.Hops-1)
			capabilityOnly := direction == ImpactDirect || (assignmentPath && hop == item.Hops-1)
			eligible.Range(func(edge Edge) bool {
				if (membershipOnly && !r.membershipEdges.IsSet(edge)) || (capabilityOnly && r.membershipEdges.IsSet(edge)) {
					return true
				}
				if edge.Probability(source, target, &all) >= r.requiredProbability {
					item.PathEdges[hop] = item.PathEdges[hop].set(edge)
				}
				return true
			})
		}
		page.Items = append(page.Items, item)
	}
	return page, nil
}

// Keep membership predecessors separate from the final capability. An object
// can be both a member and an assigned target without corrupting example paths.
func (r *ImpactResult) assignedPredecessors(ctx context.Context, root uint32, requireMembership bool) ([]uint32, []uint32, error) {
	const unseen = ^uint32(0)
	membershipPrevious, assignedVia := make([]uint32, len(r.nodes)), make([]uint32, len(r.nodes))
	for i := range r.nodes {
		membershipPrevious[i], assignedVia[i] = unseen, unseen
	}
	var queue []uint32
	if requireMembership {
		if len(r.membershipOutgoing.offsets) > 0 {
			for _, group := range r.membershipOutgoing.row(root) {
				membershipPrevious[group] = root
				queue = append(queue, group)
			}
		}
	} else {
		membershipPrevious[root] = root
		queue = append(queue, root)
	}
	for head := 0; head < len(queue); head++ {
		if head&1023 == 0 && ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		source := queue[head]
		for j, target := range r.capabilities.row(source) {
			if j&4095 == 0 && ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			if target != root && assignedVia[target] == unseen {
				assignedVia[target] = source
			}
		}
		if len(r.membershipOutgoing.offsets) == 0 {
			continue
		}
		for j, target := range r.membershipOutgoing.row(source) {
			if j&4095 == 0 && ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			if membershipPrevious[target] == unseen {
				membershipPrevious[target] = source
				queue = append(queue, target)
			}
		}
	}
	return membershipPrevious, assignedVia, nil
}

// RetainedBytes estimates backing storage owned by the result, excluding graph
// objects, allocator overhead, and temporary closure or inspection scratch space.
func (r *ImpactResult) RetainedBytes() uint64 {
	words := cap(r.component) + cap(r.counts) + cap(r.direct) + cap(r.assigned) + cap(r.viaGroups) + cap(r.sources) + cap(r.groupSources) + cap(r.outgoing.targets) + cap(r.incoming.targets) + cap(r.membershipIncoming.targets) + cap(r.membershipOutgoing.targets)
	offsets := cap(r.outgoing.offsets) + cap(r.incoming.offsets) + cap(r.membershipIncoming.offsets) + cap(r.membershipOutgoing.offsets)
	if len(r.capabilities.offsets) > 0 && &r.capabilities.offsets[0] != &r.outgoing.offsets[0] {
		words += cap(r.capabilities.targets)
		offsets += cap(r.capabilities.offsets)
	}
	// Offsets and the retained snapshot's node pointers use native words.
	return uint64(words)*4 + uint64(cap(r.targetClasses)+cap(r.sourceClasses))*2 +
		uint64(cap(r.nodes)+offsets)*uint64(strconv.IntSize/8)
}
