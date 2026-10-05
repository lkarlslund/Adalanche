package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
)

// SourceCollection is the cause of edges a machine's own collection shows;
// the detail names what it listed. The machine is found from the edge (see
// collectionOrigin), so the same listing on every machine is one cause.
var SourceCollection = engine.NewSourceKind("Machine collection")

// Collected is the cause of an edge from a machine's collection.
func Collected(detail string) engine.Source {
	return engine.Source{Kind: SourceCollection, Detail: detail}
}

func init() {
	engine.RegisterSourceOrigin(SourceCollection, collectionOrigin)
}

// collectionOrigin finds the machine whose collection an edge came from: an
// endpoint that is a machine (the target first, as for a right on the
// machine), or else the machine above the target or the source.
func collectionOrigin(from, to *engine.Node, s engine.EdgeSource) *engine.Node {
	if s.About != nil {
		return s.About
	}
	for _, n := range []*engine.Node{to, from} {
		if n.Type() == analyze.ObjectTypeMachine {
			return n
		}
	}
	for _, n := range []*engine.Node{to, from} {
		for p := n.Parent(); p != nil; p = p.Parent() {
			if p.Type() == analyze.ObjectTypeMachine {
				return p
			}
		}
	}
	return nil
}
