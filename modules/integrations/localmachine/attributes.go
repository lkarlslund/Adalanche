package localmachine

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	InstalledSoftware = engine.NewAttribute("installedSoftware")
	MACAddress        = engine.NewAttribute("mACAddress").Flag(engine.Merge)
	CollectedSettings = engine.NewAttribute("collectedSettings")

	// Facts from the machine's own policy processing, extracted at import.
	ADSite              = engine.NewAttribute("adSite").SetDescription("AD site the machine reports it belongs to")
	GPOResultsCollected = engine.NewAttribute("gpoResultsCollected").SetDescription("The machine's computer policy results were collected")
)
