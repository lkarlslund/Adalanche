package engine

import (
	"fmt"
	"sync"
	"testing"
)

func TestIndexAddLookupAndUndupe(t *testing.T) {
	var index Index
	index.init()
	node := testNamedNode("Alpha")

	index.Add(NV("alpha"), node, false)
	index.Add(NV("alpha"), node, true)

	nodes, found := index.Lookup(NV("ALPHA"))
	if !found || nodes.Len() != 1 || nodes.First() != node {
		t.Fatal("expected index lookup to be case-insensitive and deduped")
	}
}

func TestMultiIndexAddLookupAndUndupe(t *testing.T) {
	var index MultiIndex
	index.init()
	node := testNode(Name, "Alpha", SAMAccountName, "ALPHA")

	index.Add(NV("alpha"), NV("alpha"), node, false)
	index.Add(NV("alpha"), NV("alpha"), node, true)

	nodes, found := index.Lookup(NV("ALPHA"), NV("ALPHA"))
	if !found || nodes.Len() != 1 || nodes.First() != node {
		t.Fatal("expected multi-index lookup to be case-insensitive and deduped")
	}
}

func TestIndexedGraphConcurrentIndexCreationAndLookup(t *testing.T) {
	graph := NewIndexedGraph()
	for i := 0; i < 256; i++ {
		graph.Add(testNode(Name, fmt.Sprintf("node-%d", i), SAMAccountName, fmt.Sprintf("NODE-%d", i)))
	}

	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				nameIndex := graph.GetIndex(Name)
				if nodes, found := nameIndex.Lookup(NV(fmt.Sprintf("node-%d", (worker+i)%256))); !found || nodes.Len() == 0 {
					t.Errorf("expected name index lookup to succeed")
					return
				}
				multi := graph.GetMultiIndex(Name, SAMAccountName)
				if nodes, found := multi.Lookup(
					NV(fmt.Sprintf("node-%d", (worker+i)%256)),
					NV(fmt.Sprintf("node-%d", (worker+i)%256)),
				); !found || nodes.Len() == 0 {
					t.Errorf("expected multi-index lookup to succeed")
					return
				}
			}
		}(worker)
	}
	wg.Wait()
}
