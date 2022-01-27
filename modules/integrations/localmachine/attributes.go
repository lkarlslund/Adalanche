package localmachine

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	InstalledSoftware = engine.NewAttribute("installedSoftware").Multi()
	MACAddress        = engine.NewAttribute("MACAddress").Multi().Merge()
)
