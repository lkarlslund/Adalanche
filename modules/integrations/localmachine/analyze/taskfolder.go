package analyze

import (
	"encoding/json"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// taskFolderFullControl is the mask that means full control over a task
// folder: the file "all access" right or the raw generic-all bit.
const taskFolderFullControl engine.Mask = 0x1f01ff

// EdgeTaskFolderControl: the account has full control over a scheduled-task
// folder, which lets it tamper with the folder's tasks. It is only raised for
// specific principals, not the broad groups a default ACL grants, so it marks
// an abnormal grant rather than normal task creation.
var EdgeTaskFolderControl = engine.NewEdge("TaskFolderControl").RegisterProbabilityCalculator(activedirectory.OnlyIfTargetAccountEnabled(activedirectory.FixedProbability(40))).Tag("Pivot").Describe("Has full control over a scheduled-task folder, outside the groups a default ACL grants")

// controllableTrustee reports whether the SID is a principal a person could
// act as: a domain or local user or group (authority 21). This excludes the
// everyone-style groups and admins a default folder ACL lists, and the
// service and virtual accounts (authorities 80, 90, 96) that routinely hold
// full control over their own task folders, which would otherwise be noise.
func controllableTrustee(sid windowssecurity.SID) bool {
	return sid.Component(2) == 21
}

func importTaskFolders(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) error {
	for _, raw := range a.Categories["task-payloads"].Records {
		var r struct {
			Kind string
			Path string
			SDDL string
		}
		if json.Unmarshal(raw, &r) != nil || r.Kind != "task-folder" || r.SDDL == "" {
			continue
		}
		acl, err := engine.ParseSDDL(r.SDDL)
		if err != nil || acl.ContainsDeny() {
			continue
		}
		for _, ace := range acl.Entries {
			if ace.Type != engine.ACETYPE_ACCESS_ALLOWED || ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE != 0 {
				continue
			}
			if !controllableTrustee(ace.SID) {
				continue
			}
			if ace.Mask&taskFolderFullControl != taskFolderFullControl && ace.Mask&genericAll == 0 {
				continue
			}
			folder := r.Path
			if folder == "" {
				folder = `\`
			}
			tx.EdgeBecause(tx.FindOrAddAdjacentSID(ace.SID, machine), machine, EdgeTaskFolderControl, Collected("full control over task folder "+folder))
		}
	}
	return nil
}

func init() {
	RegisterAssessmentImporter(importTaskFolders)
}
