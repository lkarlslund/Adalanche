package analyze

import "github.com/lkarlslund/adalanche/modules/engine"

// SourceCollection is the cause of edges a machine's own collection shows;
// the source is about the machine, and the detail names what it listed.
var SourceCollection = engine.NewSourceKind("Machine collection")

func collected(machine engine.NodeRef, detail string) engine.Source {
	return engine.Source{Kind: SourceCollection, About: machine, Detail: detail}
}
