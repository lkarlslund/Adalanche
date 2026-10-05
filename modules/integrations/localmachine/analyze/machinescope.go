package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// MachineScope finds or adds principals by SID as a machine collection sees
// them, and places the machine's own principals (built-in SIDs and its
// local accounts) under the machine in the tree. Domain accounts are left
// where the directory puts them, and so are a domain controller's
// principals, which are the domain's.
type MachineScope struct {
	tx               *engine.Tx
	machine          engine.TxNode
	localSID         windowssecurity.SID
	domainController bool
}

// NewMachineScope returns the scope of a machine imported from info.
func NewMachineScope(tx *engine.Tx, machine engine.TxNode, info lm.Info) MachineScope {
	localSID, _ := windowssecurity.ParseStringSID(info.Machine.LocalSID)
	return MachineScope{tx: tx, machine: machine, localSID: localSID, domainController: isDomainController(info)}
}

// Principal finds or adds the principal for sid relative to the machine.
func (s MachineScope) Principal(sid windowssecurity.SID) engine.TxNode {
	principal := s.tx.FindOrAddAdjacentSID(sid, s.machine)
	if s.local(sid) {
		principal.ChildOf(s.machine)
	}
	return principal
}

// local reports whether sid names one of the machine's own principals.
func (s MachineScope) local(sid windowssecurity.SID) bool {
	if s.domainController || sid.IsBlank() {
		return false
	}
	if sid.Component(2) == 21 {
		return !s.localSID.IsBlank() && sid.StripRID() == s.localSID
	}
	return true
}

// isDomainController reports whether the collection comes from a domain
// controller.
func isDomainController(info lm.Info) bool {
	if info.Machine.ProductType != "" {
		return strings.EqualFold(info.Machine.ProductType, "LANMANNT")
	}
	// Account Operators exists only locally on domain controllers.
	for _, group := range info.Groups {
		if group.SID == "S-1-5-32-548" {
			return true
		}
	}
	return false
}
