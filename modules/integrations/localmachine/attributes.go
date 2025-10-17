package localmachine

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	InstalledSoftware = engine.NewAttribute("installedSoftware")
	MACAddress        = engine.NewAttribute("mACAddress").Flag(engine.Merge)
)
