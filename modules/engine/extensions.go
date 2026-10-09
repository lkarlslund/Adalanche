package engine

import (
	"fmt"
	"sync"
)

// Extension returns graph-local extension state. Keys must be comparable;
// extensions should use their own private key types to avoid collisions.
func (g *IndexedGraph) Extension(key any) (any, bool) {
	return g.extensions.Load(key)
}

// SetExtension publishes graph-local extension state. A nil value removes it.
// Callers are responsible for synchronizing mutable values.
func (g *IndexedGraph) SetExtension(key, value any) {
	if value == nil {
		g.extensions.Delete(key)
		return
	}
	g.extensions.Store(key, value)
}

var mergePreparers struct {
	sync.RWMutex
	items []func([]*IndexedGraph) error
}

// RegisterMergePreparer registers a step that runs once after the loader
// processors and before references are resolved, on the loaded graph. It is for decisions that need all loaders' data, such as
// which of several machine collections is the current one. It changes the
// graphs only through transactions, and its outcome must depend only on the
// data, never on the order of the graphs.
func RegisterMergePreparer(prepare func([]*IndexedGraph) error) {
	if prepare == nil {
		panic("nil merge preparer")
	}
	mergePreparers.Lock()
	defer mergePreparers.Unlock()
	mergePreparers.items = append(mergePreparers.items, prepare)
}

func prepareMerge(graphs []*IndexedGraph) error {
	mergePreparers.RLock()
	callbacks := append([]func([]*IndexedGraph) error(nil), mergePreparers.items...)
	mergePreparers.RUnlock()
	for _, prepare := range callbacks {
		if err := prepare(graphs); err != nil {
			return fmt.Errorf("prepare merge: %w", err)
		}
	}
	return nil
}

var graphFinalizers struct {
	sync.RWMutex
	items []func(*IndexedGraph) error
}

var graphAttributeCalculators struct {
	sync.RWMutex
	items []func(*IndexedGraph) error
}

// RegisterGraphAttributeCalculator registers an initialization-time calculation
// after all topology processors and before read-only finalizers. Calculators may
// publish node attributes, but must not change graph topology. Errors abort Run.
func RegisterGraphAttributeCalculator(calculate func(*IndexedGraph) error) {
	if calculate == nil {
		panic("nil graph attribute calculator")
	}
	graphAttributeCalculators.Lock()
	defer graphAttributeCalculators.Unlock()
	graphAttributeCalculators.items = append(graphAttributeCalculators.items, calculate)
}

func calculateGraphAttributes(g *IndexedGraph) error {
	graphAttributeCalculators.RLock()
	callbacks := append([]func(*IndexedGraph) error(nil), graphAttributeCalculators.items...)
	graphAttributeCalculators.RUnlock()
	for _, calculate := range callbacks {
		if err := calculate(g); err != nil {
			return fmt.Errorf("calculate graph attributes: %w", err)
		}
	}
	return nil
}

// RegisterGraphFinalizer registers an initialization-time extension that runs
// after all graph processors. Finalizers must treat the graph as read-only.
// An error prevents Run from returning the graph as successfully analyzed.
func RegisterGraphFinalizer(finalize func(*IndexedGraph) error) {
	if finalize == nil {
		panic("nil graph finalizer")
	}
	graphFinalizers.Lock()
	defer graphFinalizers.Unlock()
	graphFinalizers.items = append(graphFinalizers.items, finalize)
}

func finalizeGraph(g *IndexedGraph) error {
	graphFinalizers.RLock()
	callbacks := append([]func(*IndexedGraph) error(nil), graphFinalizers.items...)
	graphFinalizers.RUnlock()
	for _, finalize := range callbacks {
		if err := finalize(g); err != nil {
			return fmt.Errorf("finalize graph: %w", err)
		}
	}
	return nil
}
