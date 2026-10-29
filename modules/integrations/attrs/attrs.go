package attrs

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	// DomainJoinedSID links a machine to its computer account, and is the
	// stable key a machine is known by: the directory-made node and the
	// collection(s) claiming the account all carry it, so tags on a machine
	// hold across loads whether or not the node has an objectSid of its own.
	// Several machines can share one (a machine collected more than once, or
	// clones); the key then resolves to the current one (PrimaryMachineFor).
	DomainJoinedSID = engine.NewAttribute("domainJoinedSID").Flag(engine.Single).Type(engine.AttributeTypeSID)
	// PrimaryMachineFor is the computer account SID on the one machine node
	// that stands for that account: the machine made from the directory, and
	// the current collection claiming the account, which merge into one.
	PrimaryMachineFor = engine.NewAttribute("primaryMachineFor").Flag(engine.Single, engine.Merge)
)

func init() {
	// A machine's key is its domain computer SID, taking precedence over the
	// node's own objectSid (a clone-prone local machine SID).
	engine.RegisterPrimaryID(DomainJoinedSID, engine.ObjectSid)
}
