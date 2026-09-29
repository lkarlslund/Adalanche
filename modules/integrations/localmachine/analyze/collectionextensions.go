package analyze

import (
	"fmt"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

type CollectionExtensionImporter func(*engine.IndexedGraph, *engine.Node, localmachine.Info, []byte) error

var collectionExtensions sync.Map

// RegisterCollectionExtension installs a decoder for a versioned record name.
// The callback may be invoked concurrently for independent machine collections.
func RegisterCollectionExtension(name string, importer CollectionExtensionImporter) {
	collectionExtensions.Store(name, importer)
}

func importCollectionExtensions(g *engine.IndexedGraph, computer *engine.Node, base localmachine.Info, extensions map[string][]byte) error {
	for name, payload := range extensions {
		if importer, ok := collectionExtensions.Load(name); ok {
			if err := importer.(CollectionExtensionImporter)(g, computer, base, payload); err != nil {
				return fmt.Errorf("extension %s: %w", name, err)
			}
		} else {
			ui.Warn().Msgf("Machine collection extension %q was not analyzed", name)
		}
	}
	return nil
}
