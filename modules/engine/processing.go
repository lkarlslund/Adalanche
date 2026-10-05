package engine

import (
	"time"

	"github.com/lkarlslund/adalanche/modules/ui"
)

func getConflictAttributes() []Attribute {
	var conflicts []Attribute
	for attr := range attributeinfos {
		if Attribute(attr).HasFlag(Single) && !Attribute(attr).HasFlag(DropWhenMerging) {
			conflicts = append(conflicts, Attribute(attr))
		}
	}
	return conflicts
}

// placeOrphans puts nodes without a parent under the orphan container, and
// adds children that are not in the graph.
func placeOrphans(g *IndexedGraph, orphancontainer *Node) {
	var orphans int
	var queue []*Node
	g.Iterate(func(object *Node) bool {
		if object.Parent() == nil && object != g.Root() {
			object.childOf(orphancontainer)
			orphans++
		}
		queue = append(queue, object)
		return true
	})
	// Each node is one child of one parent, so every child is visited once;
	// children that are not in the graph are added, with their own.
	for len(queue) > 0 {
		o := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		o.Children().Iterate(func(child *Node) bool {
			if !g.Contains(child) {
				ui.Debug().Msgf("Child object %v wasn't added to index, fixed", child.Label())
				g.add(child)
				queue = append(queue, child)
			}
			return true
		})
	}
	if orphans > 0 {
		ui.Warn().Msgf("Detected %v orphan objects in final results", orphans)
	}
}

// NewAnalysisGraph returns the graph Run loads into: a root node with an
// orphan container under it.
func NewAnalysisGraph() *IndexedGraph {
	g := NewIndexedGraph()
	root := NewNode(
		Name, NV("Adalanche root node"),
		Type, NV("Root"),
	)
	g.setRoot(root)
	g.orphans = NewNode(Name, NV("Orphans"))
	g.orphans.childOf(root)
	g.add(g.orphans)
	return g
}

// FinishLoading turns what loaders committed into the analysed graph's
// starting point, after the loader-phase processors: loaders' parent claims
// are applied, merge preparers run, references are folded into the nodes
// they stand for, loader roots nobody placed anything under are removed, and
// nodes without a parent go under the orphan container.
func (g *IndexedGraph) FinishLoading() error {
	return g.finishLoading(nil)
}

// finishLoading is FinishLoading reporting how many of its steps are done.
func (g *IndexedGraph) finishLoading(report func(done, total int)) error {
	const steps = 4
	done := 0
	start := time.Now()
	timed := func(step string) {
		ui.Info().Msgf("Finishing loading: %v took %v", step, time.Since(start))
		start = time.Now()
		done++
		if report != nil {
			report(done, steps)
		}
	}
	g.applyParentClaims()
	timed("parent claims")
	if err := prepareMerge([]*IndexedGraph{g}); err != nil {
		return err
	}
	timed("merge preparers")
	// Loaders place their nodes through parent claims, so only now does a
	// loader root without children show that the loader placed nothing.
	var empty []*Node
	for _, root := range g.loadRoots {
		if root.Children().Len() == 0 {
			if parent := root.Parent(); parent != nil {
				parent.removeChild(root)
			}
			empty = append(empty, root)
		}
	}
	resolved := resolveReferencesRemoving(g, empty)
	timed("references")
	ui.Info().Msgf("After resolving references we have %v objects (%v references folded into the nodes they stand for)", g.Order(), len(resolved)-len(empty))
	if g.orphans == nil {
		g.orphans = NewNode(Name, NV("Orphans"))
		if g.Root() != nil {
			g.orphans.childOf(g.Root())
		}
		g.add(g.orphans)
	}
	placeOrphans(g, g.orphans)
	timed("orphans")
	return nil
}
