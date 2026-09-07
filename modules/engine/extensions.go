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

var graphFinalizers struct {
	sync.RWMutex
	items []func(*IndexedGraph) error
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
