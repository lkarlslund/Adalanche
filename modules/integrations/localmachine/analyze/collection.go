package analyze

import (
	"encoding/json"
	"fmt"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

// importCollectionSettings preserves each capture as an indivisible value so
// merging machines cannot combine values and outcomes from different captures.
// The assessment is left out: it runs to megabytes per machine, so whatever
// analysis needs from it is extracted at import (see RegisterAssessmentImporter).
func importCollectionSettings(machine engine.TxNode, info localmachine.Info) error {
	data, err := json.Marshal(localmachine.CollectionSettings{
		Common: info.Common, RegistryData: info.RegistryData,
		CollectionResults: info.CollectionResults, UnprivilegedCollection: info.UnprivilegedCollection,
	})
	if err != nil {
		return fmt.Errorf("encode collected settings: %w", err)
	}
	machine.SetFlex(localmachine.CollectedSettings, string(data))
	return nil
}
