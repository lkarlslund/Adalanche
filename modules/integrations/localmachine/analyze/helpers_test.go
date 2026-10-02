package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

// runTx runs fn in a transaction and commits it.
func runTx(g *engine.IndexedGraph, fn func(tx *engine.Tx)) {
	tx := g.Begin("test")
	fn(tx)
	if err := tx.Commit(); err != nil {
		panic(err)
	}
}

// importMachine imports a collection in one transaction and returns the
// committed machine node.
func importMachine(g *engine.IndexedGraph, info localmachine.Info) (*engine.Node, error) {
	tx := g.Begin("test")
	machine, err := ImportCollectorInfo(tx, info)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return machine.Node(), nil
}
