package localmachine

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	MACAddress = engine.NewAttribute("MACAddress").Multi().Merge()
)
