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
	// Keys are built once per claim; building them in every comparison
	// dominates loading at full scale.
	type keyed struct {
		parentClaim
		childHash, parentHash uint64 // of the keys, compared first
		childKey, parentKey   string
	}
	sorted := make([]keyed, len(claims))
	key := func(n *Node) string { return n.DN() + "\x00" + n.Label() }
	var wg sync.WaitGroup
	workers := runtime.GOMAXPROCS(0)
	for w := range workers {
		wg.Go(func() {
			for i := w; i < len(claims); i += workers {
				childKey, parentKey := key(claims[i].child), key(claims[i].parent)
				sorted[i] = keyed{claims[i], fnv64(childKey), fnv64(parentKey), childKey, parentKey}
			}
		})
	}
	wg.Wait()
	// The order is by key hashes (the same in every run), then keys. Claims
	// with equal keys cannot be told apart by content; a stable sort would
	// only keep commit order, which is not deterministic either.
	slices.SortFunc(sorted, func(a, b keyed) int {
		return cmp.Or(cmp.Compare(a.childHash, b.childHash), cmp.Compare(a.parentHash, b.parentHash),
			cmp.Compare(a.childKey, b.childKey), cmp.Compare(a.parentKey, b.parentKey))
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
