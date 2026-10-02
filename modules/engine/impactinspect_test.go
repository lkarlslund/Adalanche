package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
)

func TestImpactBothDirectionsAgainstBFS(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 7))
	edge := testEdge("impact-inspect").RegisterFixedProbability(100)
	for trial := range 10 {
		nodes := make([]*Node, 50)
		index := make(map[*Node]int)
		for i := range nodes {
			nodes[i] = testNamedNode(fmt.Sprint(i))
			index[nodes[i]] = i
		}
		g := testGraph(nodes...)
		matrix := make([][]bool, len(nodes))
		for i := range matrix {
			matrix[i] = make([]bool, len(nodes))
		}
		for range 100 {
			a, b := rng.IntN(len(nodes)), rng.IntN(len(nodes))
			if trial%2 == 0 && a > b {
				continue
			}
			g.edgeToEx(nodes[a], nodes[b], edge, true)
			matrix[a][b] = true
		}
		for _, workers := range []int{1, 4} {
			opts := ImpactOptions{Edges: EdgeBitmap{}.Set(edge), RequiredProbability: 100, Workers: workers,
				Categories: 3, Classify: func(n *Node) int { return index[n]%4 - 1 },
				SourceCategories: 4, SourceClassify: func(n *Node) int { return index[n]%5 - 1 }, KeepConnections: true}
			result, err := calculateImpact(context.Background(), g.freeze(), opts)
			if err != nil {
				t.Fatal(err)
			}
			metrics := make([]ImpactMetrics, len(nodes))
			result.IterateMetricsParallel(func(n *Node, m ImpactMetrics) { metrics[index[n]] = m })
			for root, node := range nodes {
				for _, mode := range []ImpactDirection{ImpactDownstream, ImpactIndirect, ImpactUpstream} {
					up := mode == ImpactUpstream
					seen := make([]bool, len(nodes))
					seen[root] = true
					queue := []int{root}
					for head := 0; head < len(queue); head++ {
						for target := range nodes {
							connected := matrix[queue[head]][target]
							if up {
								connected = matrix[target][queue[head]]
							}
							if connected && !seen[target] {
								seen[target] = true
								queue = append(queue, target)
							}
						}
					}
					categories, classify := opts.Categories, opts.Classify
					if up {
						categories, classify = opts.SourceCategories, opts.SourceClassify
					}
					for category := -1; category < categories; category++ {
						want := make(map[*Node]bool)
						for i, target := range nodes {
							class := classify(target)
							if !seen[i] || class < 0 || (category >= 0 && class != category) {
								continue
							}
							if i == root {
								continue
							}
							if mode == ImpactIndirect && (i == root || matrix[root][i]) {
								continue
							}
							want[target] = true
						}
						page, err := result.Inspect(context.Background(), node, mode, category, 0, 100)
						if err != nil || page.Total != len(want) || len(page.Items) != len(want) {
							t.Fatalf("mode %s category %d: total %d want %d: %v", mode, category, page.Total, len(want), err)
						}
						if category >= 0 {
							count := metrics[root].TotalImpact(min(category, opts.Categories-1))
							if up {
								count = metrics[root].Exposure(category)
							} else if mode == ImpactIndirect {
								count = metrics[root].Indirect(category)
							}
							if int(count) != len(want) {
								t.Fatalf("count %d want %d", count, len(want))
							}
						}
						for _, item := range page.Items {
							if !want[item.Node] {
								t.Fatal("unexpected or duplicate contributor")
							}
							delete(want, item.Node)
							if item.Hops != len(item.Path)-1 || item.PathTruncated {
								t.Fatal("incorrect path length")
							}
							start, end := node, item.Node
							if up {
								start, end = item.Node, node
							}
							if item.Path[0] != start || item.Path[len(item.Path)-1] != end {
								t.Fatal("wrong path direction")
							}
							for j := 1; j < len(item.Path); j++ {
								if len(item.PathEdges) != len(item.Path)-1 || item.PathEdges[j-1] != (EdgeBitmap{}.Set(edge)) {
									t.Fatal("missing or reversed path edge labels")
								}
								if !matrix[index[item.Path[j-1]]][index[item.Path[j]]] {
									t.Fatal("nonexistent path edge")
								}
							}
						}
						if len(page.Items) > 1 {
							paged, err := result.Inspect(context.Background(), node, mode, category, 1, 1)
							if err != nil || paged.Total != page.Total || len(paged.Items) != 1 || paged.Items[0].Node != page.Items[1].Node {
								t.Fatal("unstable pagination")
							}
						}
					}
				}
			}
		}
	}
}

func TestImpactPathEdgePolicy(t *testing.T) {
	member := testEdge("path-member").RegisterFixedProbability(100)
	control := testEdge("path-control").RegisterFixedProbability(100)
	denied := testEdge("path-denied").RegisterFixedProbability(0)
	companion := testEdge("path-companion").RegisterFixedProbability(100)
	dynamic := testEdge("path-dynamic").RegisterProbabilityCalculator(func(_, _ *Node, edges *EdgeBitmap) Probability {
		if edges.IsSet(companion) {
			return 100
		}
		return 0
	})
	root := testNode(Type, NodeTypeUser.ValueString())
	group := testNode(Type, NodeTypeGroup.ValueString())
	target := testNode(Type, NodeTypeUser.ValueString())
	g := testGraph(root, group, target)
	for _, edge := range []Edge{member, control, denied, companion, dynamic} {
		g.edgeToEx(root, group, edge, true)
		g.edgeToEx(group, target, edge, true)
	}
	r, err := calculateImpact(context.Background(), g.freeze(), ImpactOptions{
		Edges: EdgeBitmap{}.Set(member).Set(control).Set(denied).Set(dynamic), GroupMembershipEdges: EdgeBitmap{}.Set(member),
		RequiredProbability: 100, Classify: func(*Node) int { return 0 }, Categories: 1,
		SourceClassify: func(*Node) int { return 0 }, SourceCategories: 1, KeepConnections: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := r.Inspect(context.Background(), root, ImpactViaGroups, 0, 0, 25)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("via groups: %+v %v", page, err)
	}
	want := []EdgeBitmap{EdgeBitmap{}.Set(member), EdgeBitmap{}.Set(control).Set(dynamic)}
	for i, edges := range page.Items[0].PathEdges {
		if edges != want[i] {
			t.Fatalf("hop %d: %v want %v", i, edges, want[i])
		}
	}
	for _, tc := range []struct {
		root *Node
		mode ImpactDirection
		want EdgeBitmap
	}{
		{root, ImpactDirect, EdgeBitmap{}.Set(control).Set(dynamic)},
		{group, ImpactExposureViaGroups, EdgeBitmap{}.Set(member)},
	} {
		page, err := r.Inspect(context.Background(), tc.root, tc.mode, 0, 0, 25)
		if err != nil || len(page.Items) != 1 || len(page.Items[0].PathEdges) != 1 || page.Items[0].PathEdges[0] != tc.want {
			t.Fatalf("%s labels: %+v %v", tc.mode, page, err)
		}
	}
}

func TestImpactInspectionBounds(t *testing.T) {
	view, opts := impactBenchmarkGraph(1500, 1500)
	opts.KeepConnections = true
	opts.SourceClassify, opts.SourceCategories = opts.Classify, opts.Categories
	r, err := calculateImpact(context.Background(), view, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Inspect(ctx, view.nodes[0], ImpactDownstream, -1, 0, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode               ImpactDirection
		cat, offset, limit int
	}{
		{"bad", -1, 0, 1}, {ImpactDownstream, -2, 0, 1}, {ImpactDownstream, 99, 0, 1}, {ImpactDownstream, -1, -1, 1}, {ImpactDownstream, -1, 0, 101},
	} {
		if _, err := r.Inspect(context.Background(), view.nodes[0], tc.mode, tc.cat, tc.offset, tc.limit); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	for _, mode := range []ImpactDirection{ImpactDownstream, ImpactUpstream} {
		root := view.nodes[0]
		offset := 280
		if mode == ImpactUpstream {
			root = view.nodes[1499]
			offset = 0
		}
		page, err := r.Inspect(context.Background(), root, mode, -1, offset, 1)
		if err != nil || len(page.Items) != 1 || !page.Items[0].PathTruncated || len(page.Items[0].Path) != 128 {
			t.Fatalf("long path not bounded: %v", err)
		}
	}
}

func BenchmarkImpactBidirectional(b *testing.B) {
	view, opts := impactBenchmarkGraph(1000000, 1000)
	opts.KeepConnections = true
	opts.SourceClassify, opts.SourceCategories = opts.Classify, opts.Categories
	opts.Workers = 8
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := calculateImpact(context.Background(), view, opts); err != nil {
			b.Fatal(err)
		}
	}
}
