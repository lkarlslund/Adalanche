package attrs

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	// DomainJoinedSID links a machine to its computer account. Several
	// machines can share one: a machine collected more than once, or clones.
	DomainJoinedSID = engine.NewAttribute("domainJoinedSID").Flag(engine.Single)
	// PrimaryMachineFor is the computer account SID on the one machine node
	// that stands for that account: the machine made from the directory, and
	// the current collection claiming the account, which merge into one.
	PrimaryMachineFor = engine.NewAttribute("primaryMachineFor").Flag(engine.Single, engine.Merge)
)
