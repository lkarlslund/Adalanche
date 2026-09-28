package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	ad "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var EdgeTaskActionWrite = engine.NewEdge("TaskActionWrite").RegisterFixedProbability(100).Tag("Pivot").Describe("Can modify an executable used by an enabled task; activation still depends on its trigger")

func importTaskExecution(g *engine.IndexedGraph, machine, taskNode *engine.Node, task lm.RegisteredTask) {
	if !task.Enabled || !task.Definition.Settings.Enabled {
		return
	}
	p := task.Definition.Principal
	if p.LogonType != TASK_LOGON_PASSWORD && p.LogonType != TASK_LOGON_SERVICE_ACCOUNT && p.LogonType != TASK_LOGON_INTERACTIVE_TOKEN && p.LogonType != TASK_LOGON_S4U && p.LogonType != TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD {
		return
	}
	var account *engine.Node
	name := p.UserID
	switch strings.ToUpper(name) {
	case "SYSTEM", "NT AUTHORITY\\SYSTEM":
		if p.RunLevel != 1 {
			return
		}
		account = g.FindOrAddAdjacentSID(windowssecurity.SystemSID, machine)
	case "LOCAL SERVICE", "NT AUTHORITY\\LOCAL SERVICE":
		account = g.FindOrAddAdjacentSID(windowssecurity.LocalServiceSID, machine)
	case "NETWORK SERVICE", "NT AUTHORITY\\NETWORK SERVICE":
		account = g.FindOrAddAdjacentSID(windowssecurity.NetworkServiceSID, machine)
	default:
		if sid, err := windowssecurity.ParseStringSID(name); err == nil {
			account = g.FindOrAddAdjacentSID(sid, machine)
		} else if strings.Contains(name, `\`) {
			if strings.HasPrefix(name, `.\`) {
				name = machine.Label() + name[1:]
			}
			account, _ = g.FindOrAdd(engine.DownLevelLogonName, engine.NV(name))
		} else if strings.Contains(name, "@") {
			account, _ = g.FindOrAdd(engine.UserPrincipalName, engine.NV(name))
		}
	}
	if account == nil {
		return
	}
	g.EdgeTo(taskNode, account, ad.EdgeAuthenticatesAs)
	for _, action := range task.Definition.Actions {
		acl, err := engine.ParseACL(action.PathDACL)
		if err != nil {
			continue
		}
		if !plainAllowACL(acl) {
			continue
		}
		for _, ace := range acl.Entries {
			if ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE != 0 || localAdministratorSID(ace.SID) {
				continue
			}
			if ace.Mask&(engine.FILE_WRITE_DATA|engine.Mask(0x40000000|0x10000000)) == 0 {
				continue
			}
			writer := g.FindOrAddAdjacentSID(ace.SID, machine)
			g.EdgeTo(writer, taskNode, EdgeTaskActionWrite)
		}
	}
}

// Effective access with deny/conditional ACEs requires token evaluation. Do not
// turn a partially understood task permission into a takeover relationship.
func plainAllowACL(acl engine.ACL) bool {
	for _, ace := range acl.Entries {
		if ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE == 0 && ace.Type != engine.ACETYPE_ACCESS_ALLOWED {
			return false
		}
	}
	return true
}

// locallyDeniedLogon handles known local token membership. Domain nesting and
// partial group exclusions remain recorded evidence, not assumed absent.
func locallyDeniedLogon(info lm.Info, principal, denyRight string) bool {
	denied := map[string]bool{}
	for _, p := range info.Privileges {
		if p.Name == denyRight {
			for _, sid := range p.AssignedSIDs {
				denied[sid] = true
			}
		}
	}
	if len(denied) == 0 {
		return false
	}
	seen := map[string]bool{}
	queue := []string{principal}
	for len(queue) > 0 {
		sid := queue[0]
		queue = queue[1:]
		if seen[sid] {
			continue
		}
		seen[sid] = true
		if denied[sid] || denied[windowssecurity.EveryoneSID.String()] || denied[windowssecurity.AuthenticatedUsersSID.String()] {
			return true
		}
		for _, group := range info.Groups {
			for _, member := range group.Members {
				if member.SID == sid {
					queue = append(queue, group.SID)
				}
			}
		}
	}
	return false
}
