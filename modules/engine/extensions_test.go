package engine

import (
	"errors"
	"sync"
	"testing"
)

func TestGraphExtensionsAreLocal(t *testing.T) {
	type key struct{}
	a, b := NewIndexedGraph(), NewIndexedGraph()
	a.SetExtension(key{}, "value")
	if got, ok := a.Extension(key{}); !ok || got != "value" {
		t.Fatalf("extension = %v, %v", got, ok)
	}
	if _, ok := b.Extension(key{}); ok {
		t.Fatal("extension leaked between graphs")
	}
	a.SetExtension(key{}, nil)
	if _, ok := a.Extension(key{}); ok {
		t.Fatal("extension not removed")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				a.SetExtension(key{}, "value")
				a.Extension(key{})
				a.SetExtension(key{}, nil)
			}
		})
	}
	wg.Wait()
}

func TestGraphFinalizerFailure(t *testing.T) {
	graphFinalizers.Lock()
	previous := graphFinalizers.items
	graphFinalizers.items = nil
	graphFinalizers.Unlock()
	t.Cleanup(func() {
		graphFinalizers.Lock()
		graphFinalizers.items = previous
		graphFinalizers.Unlock()
	})
	want := errors.New("extension failed")
	g := NewIndexedGraph()
	RegisterGraphFinalizer(func(got *IndexedGraph) error {
		if got != g {
			t.Fatal("wrong graph")
		}
		return want
	})
	RegisterGraphFinalizer(func(*IndexedGraph) error { t.Fatal("continued after failure"); return nil })
	if err := finalizeGraph(g); !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
}

func TestGraphAttributeCalculatorFailure(t *testing.T) {
	graphAttributeCalculators.Lock()
	previous := graphAttributeCalculators.items
	graphAttributeCalculators.items = nil
	graphAttributeCalculators.Unlock()
	t.Cleanup(func() {
		graphAttributeCalculators.Lock()
		graphAttributeCalculators.items = previous
		graphAttributeCalculators.Unlock()
	})
	g := testGraph(testNamedNode("calculated"))
	want := errors.New("calculation failed")
	RegisterGraphAttributeCalculator(func(got *IndexedGraph) error {
		if got != g {
			t.Fatal("wrong graph")
		}
		return want
	})
	RegisterGraphAttributeCalculator(func(*IndexedGraph) error { t.Fatal("continued after failure"); return nil })
	if err := calculateGraphAttributes(g); !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
}
