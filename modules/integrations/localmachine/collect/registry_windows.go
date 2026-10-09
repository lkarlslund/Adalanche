package collect

import (
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func CollectRegistryItems() localmachine.RegistryData {
	return CollectRegistryItemsWithResults(make(basedata.CollectionResults))
}

// CollectRegistryItemsWithResults retains per-value and enumeration outcomes.
// outcomes must be initialized and exclusively owned by the caller.
func CollectRegistryItemsWithResults(outcomes basedata.CollectionResults) localmachine.RegistryData {
	return collectRegistryItems(windowssecurity.ReadRegistryKey, windowssecurity.ReadRegistrySubKeyNames, outcomes)
}
