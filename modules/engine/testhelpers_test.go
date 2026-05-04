package engine

import (
	"fmt"
	"testing"
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
		g.Add(node)
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
