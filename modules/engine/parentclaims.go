package engine

import (
	"cmp"
	"runtime"
	"slices"
	"sync"
)

type parentClaim struct {
	child, parent *Node
}

func (g *IndexedGraph) claimParent(child, parent *Node) {
	g.parentClaimsMutex.Lock()
	g.parentClaims = append(g.parentClaims, parentClaim{child, parent})
	g.parentClaimsMutex.Unlock()
}

// applyParentClaims gives nodes that still have no parent the parent a
// loader claimed for them. Claims are taken in an order that comes from the
// nodes' content, so when several loaders claim different parents for one
// node, the outcome does not depend on which loader committed first. Run
// applies them after the processors that place the directory's objects.
func (g *IndexedGraph) applyParentClaims() {
	g.parentClaimsMutex.Lock()
	claims := g.parentClaims
	g.parentClaims = nil
	g.parentClaimsMutex.Unlock()
	// Key hashes are computed once per claim; building keys in every comparison
	// dominates loading at full scale.
	type keyed struct {
		parentClaim
		childHash, parentHash uint64 // of the content keys
	}
	sorted := make([]keyed, len(claims))
	key := func(n *Node) string { return n.DN() + "\x00" + n.Label() }
	var wg sync.WaitGroup
	workers := runtime.GOMAXPROCS(0)
	for w := range workers {
		wg.Go(func() {
			for i := w; i < len(claims); i += workers {
				sorted[i] = keyed{claims[i], fnv64(key(claims[i].child)), fnv64(key(claims[i].parent))}
			}
		})
	}
	wg.Wait()
	// The order is by key hashes, the same in every run. Claims with equal
	// keys cannot be told apart by content (a stable sort would only keep
	// commit order, which is not deterministic either), and two different
	// keys sharing a 64-bit hash is not a practical concern.
	slices.SortFunc(sorted, func(a, b keyed) int {
		return cmp.Or(cmp.Compare(a.childHash, b.childHash), cmp.Compare(a.parentHash, b.parentHash))
	})
	for _, c := range sorted {
		if c.child.Parent() == nil && c.child != c.parent {
			c.child.childOf(c.parent)
		}
	}
}

// fnv64 is FNV-1a: a hash with no per-process seed, for orders that must be
// the same in every run.
func fnv64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
