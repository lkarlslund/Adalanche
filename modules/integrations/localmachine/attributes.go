package localmachine

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	InstalledSoftware = engine.NewAttribute("installedSoftware")
	MACAddress        = engine.NewAttribute("mACAddress").Flag(engine.Merge, engine.Fuzzy)
	CollectedSettings = engine.NewAttribute("collectedSettings")
	CollectedAt       = engine.NewAttribute("collectedAt").Flag(engine.Single).SetDescription("When the machine collection was made")
	SMBIOSUUID        = engine.NewAttribute("smbiosUUID").Flag(engine.Single).SetDescription("System UUID from the firmware; differs between clones of a virtual machine")

	// Facts from the machine's own policy processing, extracted at import.
	ADSite              = engine.NewAttribute("adSite").SetDescription("AD site the machine reports it belongs to")
	GPOResultsCollected = engine.NewAttribute("gpoResultsCollected").SetDescription("The machine's computer policy results were collected")
)
