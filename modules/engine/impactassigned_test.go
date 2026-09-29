package engine

import (
	"context"
	"fmt"
	"testing"
)

func TestAssignedImpactExample(t *testing.T) {
	member := testEdge("assigned-member").RegisterFixedProbability(100)
	control := testEdge("assigned-control").RegisterFixedProbability(100)
	graph := NewIndexedGraph()
	root := graph.AddNew(Name, "operator", Type, NodeTypeUser.ValueString())
	group := graph.AddNew(Name, "role", Type, NodeTypeGroup.ValueString())
	nested := graph.AddNew(Name, "nested role", Type, NodeTypeGroup.ValueString())
	graph.EdgeToEx(root, group, member, true)
	graph.EdgeToEx(group, nested, member, true)
	graph.EdgeToEx(nested, group, member, true)
	for i := range 10 {
		account := graph.AddNew(Name, fmt.Sprintf("account-%d", i), Type, NodeTypeUser.ValueString())
		if i < 2 {
			graph.EdgeToEx(root, account, control, true)
		}
		graph.EdgeToEx(nested, account, control, true) // overlapping assignments
		for j := range 10 {
			machine := graph.AddNew(Name, fmt.Sprintf("machine-%d-%d", i, j), Type, NodeTypeMachine.ValueString())
			graph.EdgeToEx(account, machine, control, true)
			graph.EdgeToEx(machine, root, control, true) // takeover cycle must not inflate assigned reach
		}
	}
	classify := func(n *Node) int {
		if n.Type() == NodeTypeGroup {
			return -1
		}
		return 0
	}
	for _, workers := range []int{1, 4} {
		r, err := CalculateImpact(context.Background(), graph.Freeze(), ImpactOptions{Edges: EdgeBitmap{}.Set(member).Set(control), RequiredProbability: 100,
			GroupMembershipEdges: EdgeBitmap{}.Set(member), Classify: classify, Categories: 1, KeepConnections: true, Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		r.IterateMetricsParallel(func(n *Node, m ImpactMetrics) {
			if m.DirectImpact(0) > m.Assigned[0] || m.Assigned[0]+m.Consequential(0) != m.TotalImpact(0) {
				t.Error("partition invariant failed")
			}
			if n == root && (m.DirectImpact(0) != 2 || m.ViaGroups[0] != 10 || m.Assigned[0] != 10 || m.Consequential(0) != 100 || m.TotalImpact(0) != 110) {
				t.Errorf("unexpected counts: direct %d via groups %d assigned %d consequential %d total %d", m.DirectImpact(0), m.ViaGroups[0], m.Assigned[0], m.Consequential(0), m.TotalImpact(0))
			}
		})
		for mode, want := range map[ImpactDirection]int{ImpactDirect: 2, ImpactAssigned: 10, ImpactViaGroups: 10, ImpactConsequential: 100, ImpactDownstream: 110} {
			page, err := r.Inspect(context.Background(), root, mode, 0, 0, 100)
			if err != nil || page.Total != want {
				t.Fatalf("%s total %d want %d: %v", mode, page.Total, want, err)
			}
		}
	}
}

func TestAssignedImpactDistinguishesCompanionEdges(t *testing.T) {
	membership := testEdge("assigned-companion-membership").RegisterFixedProbability(100)
	denied := testEdge("assigned-companion-denied").RegisterFixedProbability(0)
	control := testEdge("assigned-companion-control").RegisterFixedProbability(100)
	root, group, target := testNamedNode("source"), testNode(Type, NodeTypeGroup.ValueString()), testNamedNode("target")
	g := testGraph(root, group, target)
	g.EdgeToEx(root, group, membership, true)
	g.EdgeToEx(root, group, denied, true)
	g.EdgeToEx(group, target, control, true)
	r, err := CalculateImpact(context.Background(), g.Freeze(), ImpactOptions{Edges: EdgeBitmap{}.Set(membership).Set(denied).Set(control), RequiredProbability: 100,
		GroupMembershipEdges: EdgeBitmap{}.Set(membership), Classify: func(*Node) int { return 0 }, Categories: 1, KeepConnections: true})
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.Inspect(context.Background(), root, ImpactDirect, -1, 0, 25)
	if err != nil || page.Total != 0 {
		t.Fatal("membership promoted an ineligible companion capability")
	}
	page, err = r.Inspect(context.Background(), root, ImpactAssigned, -1, 0, 25)
	if err != nil || page.Total != 1 || page.Items[0].Node != target {
		t.Fatal("membership assignment missing")
	}
}

func TestAssignedPathPaginationAndTruncation(t *testing.T) {
	member := testEdge("assigned-long-member").RegisterFixedProbability(100)
	control := testEdge("assigned-long-control").RegisterFixedProbability(100)
	g := NewIndexedGraph()
	root := g.AddNew(Name, "source", Type, NodeTypeUser.ValueString())
	previous := root
	for range 150 {
		group := g.AddNew(Type, NodeTypeGroup.ValueString())
		g.EdgeToEx(previous, group, member, true)
		previous = group
	}
	for range 3 {
		target := g.AddNew(Type, NodeTypeUser.ValueString())
		g.EdgeToEx(previous, target, control, true)
	}
	r, err := CalculateImpact(context.Background(), g.Freeze(), ImpactOptions{Edges: EdgeBitmap{}.Set(member).Set(control), RequiredProbability: 100,
		GroupMembershipEdges: EdgeBitmap{}.Set(member), Classify: func(n *Node) int {
			if n.Type() == NodeTypeGroup {
				return -1
			}
			return 0
		}, Categories: 1, KeepConnections: true})
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.Inspect(context.Background(), root, ImpactAssigned, 0, 1, 1)
	if err != nil || page.Total != 3 || len(page.Items) != 1 {
		t.Fatalf("page: %+v %v", page, err)
	}
	item := page.Items[0]
	if item.Hops != 151 || !item.PathTruncated || len(item.Path) != 128 || item.Path[0] != root {
		t.Fatal("long assigned example not bounded correctly")
	}
	if len(item.PathEdges) != len(item.Path)-1 {
		t.Fatal("truncated path edges are misaligned")
	}
	for _, edges := range item.PathEdges {
		if edges != (EdgeBitmap{}.Set(member)) {
			t.Fatal("truncated membership prefix labelled as final capability")
		}
	}
	page, err = r.Inspect(context.Background(), root, ImpactViaGroups, 0, 1, 1)
	if err != nil || page.Total != 3 || len(page.Items) != 1 || page.Items[0].Hops != 151 || !page.Items[0].PathTruncated {
		t.Fatalf("long via groups page: %+v %v", page, err)
	}
	page, err = r.Inspect(context.Background(), root, ImpactConsequential, 0, 0, 25)
	if err != nil || page.Total != 0 {
		t.Fatal("membership hops counted as consequential")
	}
}

func TestImpactViaGroupsWithoutMembershipPolicy(t *testing.T) {
	control := testEdge("via-groups-no-membership").RegisterFixedProbability(100)
	a, b := testNamedNode("source"), testNamedNode("target")
	g := testGraph(a, b)
	g.EdgeToEx(a, b, control, true)
	r, err := CalculateImpact(context.Background(), g.Freeze(), ImpactOptions{
		Edges: EdgeBitmap{}.Set(control), RequiredProbability: 100,
		Classify: func(*Node) int { return 0 }, Categories: 1, KeepConnections: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.IterateMetricsParallel(func(n *Node, m ImpactMetrics) {
		if m.ViaGroups[0] != 0 {
			t.Error("capability-only path counted as via groups")
		}
	})
	page, err := r.Inspect(context.Background(), a, ImpactViaGroups, -1, 0, 25)
	if err != nil || page.Total != 0 {
		t.Fatalf("via groups without membership: %+v %v", page, err)
	}
}

func TestImpactViaGroupsCycleWitness(t *testing.T) {
	member := testEdge("via-groups-cycle-member").RegisterFixedProbability(100)
	control := testEdge("via-groups-cycle-control").RegisterFixedProbability(100)
	root, group := testNode(Type, NodeTypeGroup.ValueString()), testNode(Type, NodeTypeGroup.ValueString())
	target := testNode(Type, NodeTypeUser.ValueString())
	g := testGraph(root, group, target)
	g.EdgeToEx(root, group, member, true)
	g.EdgeToEx(group, root, member, true)
	g.EdgeToEx(root, target, control, true)
	r, err := CalculateImpact(context.Background(), g.Freeze(), ImpactOptions{
		Edges: EdgeBitmap{}.Set(member).Set(control), GroupMembershipEdges: EdgeBitmap{}.Set(member),
		RequiredProbability: 100, Classify: func(n *Node) int {
			if n == target {
				return 0
			}
			return -1
		}, Categories: 1, KeepConnections: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.Inspect(context.Background(), root, ImpactViaGroups, 0, 0, 25)
	if err != nil || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("cycle contributors: %+v %v", page, err)
	}
	item := page.Items[0]
	want := []*Node{root, group, root, target}
	if item.Hops != 3 || len(item.Path) != len(want) {
		t.Fatalf("cycle path: %+v", item)
	}
	for i, node := range want {
		if item.Path[i] != node {
			t.Fatalf("cycle path node %d differs", i)
		}
	}
}
