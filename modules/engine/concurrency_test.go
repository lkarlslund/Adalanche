package engine

import (
	"fmt"
	"sync"
	"testing"
)

func TestIndexedGraphConcurrentFindMultiOrAddReturnsSingleNode(t *testing.T) {
	graph := NewIndexedGraph()

	var wg sync.WaitGroup
	results := make(chan *Node, 16*32)

	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 32; i++ {
				nodes, _ := graph.FindMultiOrAdd(Name, NV("shared-node"), func() *Node {
					return NewNode(Name, NV("shared-node"), SAMAccountName, NV("SHARED-NODE"))
				})
				results <- nodes.First()
			}
		}()
	}

	wg.Wait()
	close(results)

	var first *Node
	for node := range results {
		if node == nil {
			t.Fatal("expected returned node")
		}
		if first == nil {
			first = node
			continue
		}
		if node != first {
			t.Fatalf("expected all callers to observe the same node, got %p and %p", first, node)
		}
	}

	if graph.Order() != 1 {
		t.Fatalf("expected one node in graph, got %d", graph.Order())
	}
}

func TestIndexedGraphConcurrentFindTwoMultiOrAddReturnsSingleNode(t *testing.T) {
	graph := NewIndexedGraph()

	var wg sync.WaitGroup
	results := make(chan *Node, 16*32)

	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 32; i++ {
				nodes, _ := graph.FindTwoMultiOrAdd(Name, NV("shared-node"), SAMAccountName, NV("shared-node"), func() *Node {
					return NewNode(Name, NV("shared-node"), SAMAccountName, NV("SHARED-NODE"))
				})
				results <- nodes.First()
			}
		}()
	}

	wg.Wait()
	close(results)

	var first *Node
	for node := range results {
		if node == nil {
			t.Fatal("expected returned node")
		}
		if first == nil {
			first = node
			continue
		}
		if node != first {
			t.Fatalf("expected all callers to observe the same node, got %p and %p", first, node)
		}
	}

	if graph.Order() != 1 {
		t.Fatalf("expected one node in graph, got %d", graph.Order())
	}
}

func TestIndexedGraphConcurrentBulkLoadAndFlush(t *testing.T) {
	edgeType := testEdge("bulk-race")
	nodes := make([]*Node, 0, 64)
	for i := 0; i < 64; i++ {
		nodes = append(nodes, testNamedNode(fmt.Sprintf("node-%d", i)))
	}
	graph := testGraph(nodes...)

	if !graph.BulkLoadEdges(true) {
		t.Fatal("expected bulk loading to start")
	}

	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for step := 0; step < 128; step++ {
				from := nodes[(worker+step)%len(nodes)]
				to := nodes[(worker+step+1)%len(nodes)]
				graph.EdgeToEx(from, to, edgeType, true)
				if step%8 == 0 {
					graph.FlushEdges()
				}
			}
		}(worker)
	}

	wg.Wait()

	if !graph.BulkLoadEdges(false) {
		t.Fatal("expected bulk loading to stop")
	}

	if graph.Size() == 0 {
		t.Fatal("expected concurrent bulk loading to produce edges")
	}
}

func TestNodeConcurrentAdoptAndReadDistinctChildren(t *testing.T) {
	parent := testNamedNode("Parent")
	children := make([]*Node, 0, 64)
	for i := 0; i < 64; i++ {
		children = append(children, testNamedNode(fmt.Sprintf("child-%d", i)))
	}

	var wg sync.WaitGroup

	for _, child := range children {
		wg.Add(1)
		go func(child *Node) {
			defer wg.Done()
			parent.Adopt(child)
			if child.Parent() != parent {
				t.Errorf("expected child %q parent to be assigned", child.Label())
			}
		}(child)
	}

	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 128; i++ {
				_ = parent.Children().Len()
				for _, child := range children {
					_ = child.Parent()
				}
			}
		}()
	}

	wg.Wait()

	if parent.Children().Len() != len(children) {
		t.Fatalf("expected %d children, got %d", len(children), parent.Children().Len())
	}
}
