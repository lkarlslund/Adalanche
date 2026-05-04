package collect

import (
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func CollectRegistryItems() localmachine.RegistryData {
	return collectRegistryItems(windowssecurity.ReadRegistryKey, windowssecurity.ReadRegistrySubKeyNames)
}
