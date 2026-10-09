package engine

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func testNode(attrs ...any) *Node {
	return NewNode(attrs...)
}

func testNamedNode(name string, attrs ...any) *Node {
	flex := []any{Name, name}
	flex = append(flex, attrs...)
	return NewNode(flex...)
}

func testGraph(nodes ...*Node) *IndexedGraph {
	g := NewIndexedGraph()
	for _, node := range nodes {
		g.add(node)
	}
	return g
}

func testEdge(name string) Edge {
	return NewEdge("unit-test-" + name)
}

func requirePanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}

func benchmarkNamedNode(i int) *Node {
	return NewNode(
		Name, NV(fmt.Sprintf("node-%d", i)),
		DisplayName, NV(fmt.Sprintf("Node %d", i)),
		SAMAccountName, NV(fmt.Sprintf("NODE-%d", i)),
	)
}

type syntheticGraphConfig struct {
	Seed             int64
	NodeCount        int
	ClusterCount     int
	AverageOutDegree int
	AttributeDensity int
	SIDHeavyRatio    int
}

func smallSyntheticGraphConfig() syntheticGraphConfig {
	return syntheticGraphConfig{
		Seed:             11,
		NodeCount:        64,
		ClusterCount:     4,
		AverageOutDegree: 3,
		AttributeDensity: 2,
		SIDHeavyRatio:    4,
	}
}

func mediumSyntheticGraphConfig() syntheticGraphConfig {
	return syntheticGraphConfig{
		Seed:             29,
		NodeCount:        512,
		ClusterCount:     8,
		AverageOutDegree: 6,
		AttributeDensity: 3,
		SIDHeavyRatio:    3,
	}
}

func largeSyntheticGraphConfig() syntheticGraphConfig {
	return syntheticGraphConfig{
		Seed:             53,
		NodeCount:        4096,
		ClusterCount:     32,
		AverageOutDegree: 8,
		AttributeDensity: 4,
		SIDHeavyRatio:    2,
	}
}

func buildSyntheticGraph(cfg syntheticGraphConfig) *IndexedGraph {
	if cfg.NodeCount <= 0 {
		cfg.NodeCount = 1
	}
	if cfg.ClusterCount <= 0 {
		cfg.ClusterCount = 1
	}
	if cfg.AverageOutDegree < 0 {
		cfg.AverageOutDegree = 0
	}
	if cfg.AttributeDensity < 0 {
		cfg.AttributeDensity = 0
	}
	if cfg.SIDHeavyRatio < 0 {
		cfg.SIDHeavyRatio = 0
	}

	rng := rand.New(rand.NewSource(cfg.Seed))
	graph := NewIndexedGraph()
	nodes := make([]*Node, cfg.NodeCount)
	domainContext := NV("DC=example,DC=com")
	dataSource := NV("EXAMPLE")

	for i := 0; i < cfg.NodeCount; i++ {
		cluster := i % cfg.ClusterCount
		attrs := []any{
			Name, NV(fmt.Sprintf("synthetic-node-%d", i)),
			DisplayName, NV(fmt.Sprintf("Synthetic Node %d", i)),
			SAMAccountName, NV(fmt.Sprintf("SYNTH-%d", i)),
			DomainContext, domainContext,
			DataSource, dataSource,
		}

		switch i % 3 {
		case 0:
			attrs = append(attrs, Type, NodeTypeUser.ValueString())
		case 1:
			attrs = append(attrs, Type, NodeTypeComputer.ValueString())
		default:
			attrs = append(attrs, Type, NodeTypeGroup.ValueString())
		}

		if cfg.AttributeDensity > 0 {
			attrs = append(attrs, Description, NV(fmt.Sprintf("cluster-%d", cluster)))
		}
		if cfg.AttributeDensity > 1 {
			attrs = append(attrs, DistinguishedName, NV(fmt.Sprintf("CN=synthetic-node-%d,OU=cluster-%d,DC=example,DC=com", i, cluster)))
		}
		if cfg.AttributeDensity > 2 {
			attrs = append(attrs, ObjectClass, NV("top"), NV("person"))
		}
		if cfg.AttributeDensity > 3 {
			attrs = append(attrs, DownLevelLogonName, NV(fmt.Sprintf("EXAMPLE\\SYNTH-%d", i)))
		}
		if cfg.SIDHeavyRatio > 0 && i%cfg.SIDHeavyRatio == 0 {
			sid, err := windowssecurity.ParseStringSID(fmt.Sprintf("S-1-5-21-%d-%d-%d-%d", 1000+cluster, 2000+(i%97), 3000+((i/3)%97), 4000+i))
			if err != nil {
				panic(err)
			}
			attrs = append(attrs, ObjectSid, NV(sid))
		}

		node := NewNode(attrs...)
		graph.add(node)
		nodes[i] = node
	}

	for i, from := range nodes {
		for step := 0; step < cfg.AverageOutDegree; step++ {
			targetIndex := (i + step + 1 + clusterOffset(rng, cfg.ClusterCount)) % len(nodes)
			target := nodes[targetIndex]
			if from == target {
				continue
			}
			graph.edgeToEx(from, target, syntheticEdgeForStep(step), true)
		}
	}

	return graph
}

func clusterOffset(rng *rand.Rand, clusterCount int) int {
	if clusterCount <= 1 {
		return 0
	}
	return rng.Intn(clusterCount)
}

func syntheticEdgeForStep(step int) Edge {
	switch step % 3 {
	case 0:
		return testEdge("synthetic-member")
	case 1:
		return testEdge("synthetic-admin")
	default:
		return testEdge("synthetic-session")
	}
}

// loadGraphs is enginetest.Load for the engine's own tests.
func loadGraphs(graphs ...*IndexedGraph) *IndexedGraph {
	g := NewAnalysisGraph()
	for _, src := range graphs {
		tx := NewLoadTarget(g, "test loader").Begin("test")
		handles := map[*Node]TxNode{}
		src.IterateStable(func(n *Node) bool {
			handles[n] = tx.AddIdentified(n, DistinguishedName)
			return true
		})
		src.IterateStable(func(n *Node) bool {
			src.IterateEdges(n, Out, func(to *Node, eb EdgeBitmap) bool {
				tx.SetEdge(handles[n], handles[to], eb, true)
				return true
			})
			return true
		})
		if err := tx.Commit(); err != nil {
			panic(err)
		}
	}
	if err := g.FinishLoading(); err != nil {
		panic(err)
	}
	return g
}
