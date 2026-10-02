package engine

import (
	"context"
	"math/rand/v2"
	"testing"
)

func TestImpactPartitionsAgainstTraversal(t *testing.T) {
	rng := rand.New(rand.NewPCG(51, 97))
	membership := testEdge("impact-partition-membership").RegisterFixedProbability(100)
	takeover := testEdge("impact-partition-takeover").RegisterFixedProbability(100)
	for trial := range 8 {
		nodes := make([]*Node, 32)
		index := make(map[*Node]int)
		members, all := make([][]bool, len(nodes)), make([][]bool, len(nodes))
		capabilities := make([][]bool, len(nodes))
		for i := range nodes {
			kind := NodeTypeUser
			if i%3 == 0 {
				kind = NodeTypeGroup
			}
			nodes[i] = testNode(Type, kind.ValueString())
			index[nodes[i]] = i
			members[i], all[i] = make([]bool, len(nodes)), make([]bool, len(nodes))
			capabilities[i] = make([]bool, len(nodes))
		}
		graph := testGraph(nodes...)
		for range 110 {
			a, b := rng.IntN(len(nodes)), rng.IntN(len(nodes))
			if a == b {
				continue
			} // The graph does not store self edges.
			edge := takeover
			if nodes[b].Type() == NodeTypeGroup && rng.IntN(2) == 0 {
				edge = membership
				members[a][b] = true
			}
			all[a][b] = true
			if edge == takeover {
				capabilities[a][b] = true
			}
			graph.edgeToEx(nodes[a], nodes[b], edge, true)
		}
		classify := func(n *Node) int {
			if n.Type() == NodeTypeGroup {
				return 1
			}
			return 0
		}
		options := ImpactOptions{Edges: EdgeBitmap{}.Set(membership).Set(takeover), RequiredProbability: 100,
			Classify: classify, Categories: 2, SourceClassify: classify, SourceCategories: 2,
			KeepConnections: true, Workers: 1 + trial%4, GroupMembershipEdges: EdgeBitmap{}.Set(membership)}
		result, err := calculateImpact(context.Background(), graph.freeze(), options)
		if err != nil {
			t.Fatal(err)
		}
		metrics := make([]ImpactMetrics, len(nodes))
		result.IterateMetricsParallel(func(n *Node, m ImpactMetrics) { metrics[index[n]] = m })
		for root, node := range nodes {
			traverse := func(groups bool) []bool {
				seen := make([]bool, len(nodes))
				seen[root] = true
				queue := []int{root}
				for head := 0; head < len(queue); head++ {
					current := queue[head]
					for source := range nodes {
						eligible := all[source][current]
						if groups {
							eligible = members[source][current]
						}
						if eligible && !seen[source] {
							seen[source] = true
							queue = append(queue, source)
						}
					}
				}
				seen[root] = false
				return seen
			}
			full, groups := traverse(false), traverse(true)
			outward := func(edges [][]bool) []bool {
				seen := make([]bool, len(nodes))
				seen[root] = true
				queue := []int{root}
				for head := 0; head < len(queue); head++ {
					for target, edge := range edges[queue[head]] {
						if edge && !seen[target] {
							seen[target] = true
							queue = append(queue, target)
						}
					}
				}
				return seen
			}
			membership, downstream := outward(members), outward(all)
			assigned := make([]bool, len(nodes))
			viaGroups := make([]bool, len(nodes))
			// A positive-length membership route can return to root through a cycle.
			rootViaGroup := false
			for source := range nodes {
				rootViaGroup = rootViaGroup || (membership[source] && members[source][root])
			}
			for source, member := range membership {
				if member {
					for target, capability := range capabilities[source] {
						assigned[target] = assigned[target] || capability
						if source != root || rootViaGroup {
							viaGroups[target] = viaGroups[target] || capability
						}
					}
				}
			}
			for _, mode := range []ImpactDirection{ImpactUpstream, ImpactExposureViaGroups, ImpactExposureOther, ImpactDirect, ImpactAssigned, ImpactViaGroups, ImpactConsequential, ImpactDownstream} {
				for category := -1; category < 2; category++ {
					want := make(map[*Node]bool)
					for i, n := range nodes {
						selected := full[i]
						switch mode {
						case ImpactExposureViaGroups:
							selected = groups[i]
						case ImpactExposureOther:
							selected = full[i] && !groups[i]
						case ImpactDirect:
							selected = i != root && capabilities[root][i]
						case ImpactAssigned:
							selected = i != root && assigned[i]
						case ImpactViaGroups:
							selected = i != root && viaGroups[i]
						case ImpactConsequential:
							selected = i != root && downstream[i] && !assigned[i]
						case ImpactDownstream:
							selected = i != root && downstream[i]
						}
						if selected && (category == -1 || classify(n) == category) {
							want[n] = true
						}
					}
					page, err := result.Inspect(context.Background(), node, mode, category, 0, 100)
					if err != nil || page.Total != len(want) || len(page.Items) != len(want) {
						t.Fatalf("trial %d root %d mode %s: total %d want %d: %v", trial, root, mode, page.Total, len(want), err)
					}
					if category >= 0 {
						count := metrics[root].Exposure(category)
						switch mode {
						case ImpactExposureViaGroups:
							count = metrics[root].GroupSources[category]
						case ImpactExposureOther:
							count = metrics[root].OtherExposure(category)
						case ImpactDirect:
							count = metrics[root].DirectImpact(category)
						case ImpactAssigned:
							count = metrics[root].Assigned[category]
						case ImpactViaGroups:
							count = metrics[root].ViaGroups[category]
						case ImpactConsequential:
							count = metrics[root].Consequential(category)
						case ImpactDownstream:
							count = metrics[root].TotalImpact(category)
						}
						if int(count) != len(want) {
							t.Fatalf("trial %d root %d mode %s: count %d want %d", trial, root, mode, count, len(want))
						}
					}
					for _, item := range page.Items {
						if !want[item.Node] {
							t.Fatal("unexpected contributor")
						}
						delete(want, item.Node)
						if mode == ImpactAssigned || mode == ImpactViaGroups {
							if mode == ImpactViaGroups && item.Hops < 2 {
								t.Fatal("via groups example lacks membership hop")
							}
							if len(item.Path) < 2 || item.Path[0] != node || item.Path[len(item.Path)-1] != item.Node {
								t.Fatal("incorrect assigned path endpoints")
							}
							for hop := 0; hop+1 < len(item.Path); hop++ {
								a, b := index[item.Path[hop]], index[item.Path[hop+1]]
								if hop+2 == len(item.Path) {
									if !capabilities[a][b] {
										t.Fatal("assignment lacks final capability")
									}
								} else if !members[a][b] {
									t.Fatal("assigned example contains an earlier takeover")
								}
							}
						}
						if mode == ImpactExposureViaGroups {
							for hop := 0; hop+1 < len(item.Path); hop++ {
								a, b := index[item.Path[hop]], index[item.Path[hop+1]]
								if !members[a][b] {
									t.Fatal("membership example uses a takeover step")
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestGroupExposureEmptyAndDisabled(t *testing.T) {
	member := testEdge("impact-empty-membership").RegisterFixedProbability(100)
	options := ImpactOptions{Edges: EdgeBitmap{}.Set(member), RequiredProbability: 100, Classify: func(*Node) int { return 0 }, Categories: 1,
		SourceClassify: func(*Node) int { return 0 }, SourceCategories: 1, GroupMembershipEdges: EdgeBitmap{}.Set(member), KeepConnections: true}
	if _, err := calculateImpact(context.Background(), testGraph().freeze(), options); err != nil {
		t.Fatal(err)
	}
	node := testNamedNode("sample")
	options.GroupMembershipEdges = EdgeBitmap{}
	result, err := calculateImpact(context.Background(), testGraph(node).freeze(), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.Inspect(context.Background(), node, ImpactExposureViaGroups, -1, 0, 25); err == nil {
		t.Fatal("missing partition presented as computed")
	}
}
