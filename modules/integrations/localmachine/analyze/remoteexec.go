package analyze

import (
	"encoding/json"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	ad "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// COM access-mask bits (MS-DCOM): the remote ones let an account launch or
// activate a DCOM object from off the machine, which is lateral movement.
const (
	comRightsExecuteRemote  engine.Mask = 0x4
	comRightsActivateRemote engine.Mask = 0x10
	// The raw generic-right bits as a self-relative or SDDL ACL stores them,
	// before any mapping to specific rights.
	genericExecute engine.Mask = 0x20000000
	genericAll     engine.Mask = 0x10000000
)

// EdgeRemotePowerShell: the account may open a PowerShell/WSMan remoting
// session on the machine, running code there.
var EdgeRemotePowerShell = engine.NewEdge("RemotePowerShell").RegisterProbabilityCalculator(activedirectory.OnlyIfTargetAccountEnabled(activedirectory.FixedProbability(50))).Tag("Pivot").Describe("Can open a remote PowerShell (WSMan) session on the machine and run code")

// alreadyPrivileged skips principals that already fully control the machine,
// so these edges show who else gains access.
func alreadyPrivileged(sid windowssecurity.SID) bool {
	return sid == windowssecurity.SystemSID || sid.String() == "S-1-5-32-544"
}

func importRemoteExecution(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) error {
	importDCOMRights(tx, machine, a)
	importRemoteEndpoints(tx, machine, a)
	return nil
}

func importDCOMRights(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) {
	for _, raw := range a.Categories["dcom-security"].Records {
		var r struct {
			Value              string
			SecurityDescriptor []byte
		}
		// Only launch/activation permissions grant code execution; access
		// permissions alone do not.
		if json.Unmarshal(raw, &r) != nil || !strings.Contains(r.Value, "Launch") || len(r.SecurityDescriptor) == 0 {
			continue
		}
		sd, err := engine.ParseSecurityDescriptor(r.SecurityDescriptor)
		if err != nil || sd.DACL.ContainsDeny() {
			continue
		}
		for _, ace := range sd.DACL.Entries {
			if ace.Type != engine.ACETYPE_ACCESS_ALLOWED || ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE != 0 {
				continue
			}
			if alreadyPrivileged(ace.SID) {
				continue
			}
			if ace.Mask&(comRightsExecuteRemote|comRightsActivateRemote) == 0 && ace.Mask&genericAll == 0 {
				continue
			}
			tx.EdgeBecause(tx.FindOrAddAdjacentSID(ace.SID, machine), machine, EdgeLocalDCOMRights, Collected("DCOM "+r.Value))
		}
	}
}

func importRemoteEndpoints(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) {
	for _, raw := range a.Categories["remote-endpoints"].Records {
		var r struct {
			Name                   string
			RunAsUser              string
			SecurityDescriptorSddl string
		}
		if json.Unmarshal(raw, &r) != nil || r.SecurityDescriptorSddl == "" {
			continue
		}
		acl, err := engine.ParseSDDL(r.SecurityDescriptorSddl)
		if err != nil || acl.ContainsDeny() {
			continue
		}
		// An account that can run the endpoint, if it is configured to run as
		// a fixed account, acts as that account rather than itself.
		var runAs engine.TxNode
		if sid, err := windowssecurity.ParseStringSID(strings.TrimSpace(r.RunAsUser)); err == nil && !sid.IsBlank() {
			runAs = tx.FindOrAddAdjacentSID(sid, machine)
		}
		for _, ace := range acl.Entries {
			if ace.Type != engine.ACETYPE_ACCESS_ALLOWED || ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE != 0 {
				continue
			}
			// WSMan invoke access shows in the SDDL as generic execute or all.
			if ace.Mask&(genericExecute|genericAll) == 0 {
				continue
			}
			if alreadyPrivileged(ace.SID) {
				continue
			}
			principal := tx.FindOrAddAdjacentSID(ace.SID, machine)
			tx.EdgeBecause(principal, machine, EdgeRemotePowerShell, Collected("remoting endpoint "+r.Name))
			if runAs.Valid() {
				tx.EdgeBecause(principal, runAs, ad.EdgeAuthenticatesAs, Collected("remoting endpoint "+r.Name+" RunAs account"))
			}
		}
	}
}

func init() {
	RegisterAssessmentImporter(importRemoteExecution)
}
