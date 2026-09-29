package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
)

func TestImpactMatchesTraversal(t *testing.T) {
	edge := testEdge("impact").RegisterFixedProbability(100)
	random := rand.New(rand.NewPCG(29, 17))
	for trial := range 30 {
		nodes := make([]*Node, 70)
		category := make(map[*Node]int)
		for i := range nodes {
			nodes[i] = testNamedNode(fmt.Sprint(i))
			category[nodes[i]] = random.IntN(4) - 1
		}
		g := testGraph(nodes...)
		for range 180 {
			from, to := random.IntN(len(nodes)), random.IntN(len(nodes))
			// Alternating acyclic/cyclic inputs, disconnected nodes, diamonds and fan-in.
			if trial%2 == 0 && from >= to {
				continue
			}
			g.EdgeToEx(nodes[from], nodes[to], edge, true)
		}
		view := g.Freeze()
		for _, workers := range []int{1, 4} {
			options := ImpactOptions{Edges: EdgeBitmap{}.Set(edge), RequiredProbability: 100, Categories: 3, Workers: workers,
				Classify: func(n *Node) int { return category[n] }}
			result, err := CalculateImpact(context.Background(), view, options)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range nodes {
				want := referenceImpact(view, source, options)
				if got := result.Counts(source); !slices.Equal(got, want) {
					t.Fatalf("trial %d workers %d source %s: got %v want %v", trial, workers, source.Label(), got, want)
				}
			}
			if result.Counts(nil) != nil || result.Counts(NewNode()) != nil {
				t.Fatal("accepted a node outside the graph")
			}
		}
	}
}

func referenceImpact(view *FrozenGraph, source *Node, options ImpactOptions) []uint32 {
	counts := make([]uint32, options.Categories)
	seen := map[*Node]bool{source: true}
	pending := []*Node{source}
	for len(pending) != 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if category := options.Classify(node); category >= 0 {
			counts[category]++
		}
		view.IterateEdges(node, Out, func(target *Node, edges EdgeBitmap) bool {
			if seen[target] {
				return true
			}
			edges.Intersect(options.Edges).Range(func(edge Edge) bool {
				if edge.Probability(node, target, &edges) >= options.RequiredProbability {
					seen[target] = true
					pending = append(pending, target)
					return false
				}
				return true
			})
			return true
		})
	}
	return counts
}

func TestImpactProbabilityAndCompanionRights(t *testing.T) {
	companion := testEdge("impact-companion")
	conditional := testEdge("impact-conditional").RegisterProbabilityCalculator(func(_, _ *Node, edges *EdgeBitmap) Probability {
		if edges.IsSet(companion) {
			return 100
		}
		return 0
	})
	low := testEdge("impact-low").RegisterFixedProbability(80)
	a, b, c, d := testNamedNode("a"), testNamedNode("b"), testNamedNode("c"), testNamedNode("d")
	g := testGraph(a, b, c, d)
	g.EdgeToEx(a, b, conditional, true)
	g.EdgeToEx(a, b, companion, true)
	g.EdgeToEx(b, c, conditional, true)
	g.EdgeToEx(b, d, low, true)
	options := ImpactOptions{Edges: EdgeBitmap{}.Set(conditional).Set(low), RequiredProbability: 100, Categories: 1, Classify: func(*Node) int { return 0 }}
	result, err := CalculateImpact(context.Background(), g.Freeze(), options)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Counts(a)[0]; got != 2 {
		t.Fatalf("got %d want 2", got)
	}
	options.RequiredProbability = 80
	result, err = CalculateImpact(context.Background(), g.Freeze(), options)
	if err != nil || result.Counts(a)[0] != 3 {
		t.Fatalf("lower threshold: %v, %v", result, err)
	}
}

func TestImpactCancellationAndBudget(t *testing.T) {
	view, options := impactBenchmarkGraph(2048, 64)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := CalculateImpact(ctx, view, options); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled calculation: %v, %v", result, err)
	}
	options.MaxSetBytes = 1
	if result, err := CalculateImpact(context.Background(), view, options); result != nil || err == nil {
		t.Fatalf("over-budget calculation: %v, %v", result, err)
	}
	options.MaxSetBytes = 0
	ctx, cancel = context.WithCancel(context.Background())
	original := options.Classify
	options.Classify = func(node *Node) int {
		cancel()
		return original(node)
	}
	if result, err := CalculateImpact(ctx, view, options); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during preparation: %v, %v", result, err)
	}
}

func TestImpactEmptyAndInvalid(t *testing.T) {
	options := ImpactOptions{Categories: 1, RequiredProbability: 100, Classify: func(*Node) int { return -1 }}
	result, err := CalculateImpact(context.Background(), NewIndexedGraph().Freeze(), options)
	if err != nil || result.Statistics.Nodes != 0 {
		t.Fatalf("empty graph: %v, %v", result, err)
	}
	options.Classify = func(*Node) int { return 1 }
	if _, err := CalculateImpact(context.Background(), testGraph(testNamedNode("x")).Freeze(), options); err == nil {
		t.Fatal("accepted out-of-range category")
	}
}

func TestImpactLongChainSharesSets(t *testing.T) {
	view, options := impactBenchmarkGraph(50000, 50000)
	options.Classify = func(n *Node) int {
		if n == view.nodes[len(view.nodes)-1] {
			return 0
		}
		return -1
	}
	result, err := CalculateImpact(context.Background(), view, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Counts(view.nodes[0])[0] != 1 || result.Statistics.SetBytes != 0 {
		t.Fatalf("chain should reuse singleton: %+v", result.Statistics)
	}
}

func TestImpactDenseOverlap(t *testing.T) {
	view, options := impactBenchmarkGraph(4096, 4096)
	options.Categories = 3
	options.Classify = func(node *Node) int {
		index, _ := view.graph.nodeToIndex(node)
		return int(index % 3)
	}
	for _, workers := range []int{1, 8} {
		options.Workers = workers
		result, err := CalculateImpact(context.Background(), view, options)
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range []int{0, 1, 63, 64, 1000, 4095} {
			want := referenceImpact(view, view.nodes[source], options)
			if got := result.Counts(view.nodes[source]); !slices.Equal(got, want) {
				t.Fatalf("workers %d source %d: %v want %v", workers, source, got, want)
			}
		}
	}
}

func TestImpactLargeCycle(t *testing.T) {
	view, options := impactBenchmarkGraph(10000, 10000)
	view.edges[Out][9999] = []frozenEdge{{target: 0, edge: options.Edges}}
	result, err := CalculateImpact(context.Background(), view, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Statistics.Components != 1 || result.Counts(view.nodes[0])[0] != 2000 || result.Counts(view.nodes[9999])[0] != 2000 {
		t.Fatalf("cycle: %+v", result.Statistics)
	}
}

func TestImpactSetRepresentations(t *testing.T) {
	for _, ids := range [][]uint32{{}, {0}, {63, 64, 65}, {0, 10000}, {63, 64, 65, 127, 128, 10000}} {
		builder := newImpactSetBuilder(10001)
		for _, id := range ids {
			builder.addWord(id/64, uint64(1)<<(id%64))
		}
		var allocated atomic.Uint64
		counts := make([]uint32, 3)
		set, err := builder.finish(impactSet{}, []uint32{0, 64, 128, 10001}, counts, &allocated, 0)
		if err != nil {
			t.Fatal(err)
		}
		if set.count != uint32(len(ids)) || counts[0]+counts[1]+counts[2] != uint32(len(ids)) {
			t.Fatalf("IDs %v: set %+v counts %v", ids, set, counts)
		}
		builder.union(set)
		builder.union(set)
		got := make([]uint32, 3)
		shared, err := builder.finish(set, []uint32{0, 64, 128, 10001}, got, &allocated, 0)
		if err != nil || shared.count != set.count || !slices.Equal(got, counts) {
			t.Fatalf("union changed membership: %v, %v", got, err)
		}
	}
}

// Disconnected overlapping DAGs, no SCC shortcut. Twenty percent of nodes are
// targets; four forward connections per node exercise deduplication and sharing.
func impactBenchmarkGraph(size, cluster int) (*FrozenGraph, ImpactOptions) {
	edge := testEdge("impact-benchmark").RegisterFixedProbability(100)
	ebm := EdgeBitmap{}.Set(edge)
	view := &FrozenGraph{nodes: make([]*Node, size)}
	view.graph = &IndexedGraph{nodes: view.nodes}
	view.edges[Out] = make([][]frozenEdge, size)
	backing := make([]frozenEdge, 0, size*4)
	for i := range size {
		view.nodes[i] = &Node{}
		view.graph.nodeLookup.Store(view.nodes[i], NodeIndex(i))
		start := len(backing)
		end := min((i/cluster+1)*cluster, size)
		for _, distance := range []int{1, 3, 7, 11} {
			if i+distance < end {
				backing = append(backing, frozenEdge{target: NodeIndex(i + distance), edge: ebm})
			}
		}
		view.edges[Out][i] = backing[start:]
	}
	return view, ImpactOptions{Edges: ebm, RequiredProbability: 100, Categories: 1, Classify: func(n *Node) int {
		index, _ := view.graph.nodeToIndex(n)
		if index%5 == 0 {
			return 0
		}
		return -1
	}}
}

func BenchmarkImpact(b *testing.B) {
	for _, size := range []int{10000, 100000, 1000000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			view, options := impactBenchmarkGraph(size, 1000)
			for _, workers := range []int{1, min(8, runtime.GOMAXPROCS(0))} {
				b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
					options.Workers = workers
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						result, err := CalculateImpact(context.Background(), view, options)
						if err != nil {
							b.Fatal(err)
						}
						b.ReportMetric(float64(result.Statistics.SetBytes), "set-bytes")
					}
				})
			}
		})
	}
}

func BenchmarkImpactWide(b *testing.B) {
	view, options := impactBenchmarkGraph(200000, 25000)
	for _, workers := range []int{1, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			options.Workers = workers
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				result, err := CalculateImpact(context.Background(), view, options)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(result.Statistics.SetBytes), "set-bytes")
			}
		})
	}
}

func BenchmarkImpactReferenceTraversal(b *testing.B) {
	view, options := impactBenchmarkGraph(10000, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for _, node := range view.nodes {
			_ = referenceImpact(view, node, options)
		}
	}
}

func BenchmarkImpactDenseChain(b *testing.B) {
	view, options := impactBenchmarkGraph(20000, 20000)
	options.Classify = func(*Node) int { return 0 }
	options.Workers = 8
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		result, err := CalculateImpact(context.Background(), view, options)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(result.Statistics.SetBytes), "set-bytes")
	}
}
