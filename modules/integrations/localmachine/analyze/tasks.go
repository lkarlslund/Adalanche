package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	ad "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var EdgeTaskActionWrite = engine.NewEdge("TaskActionWrite").RegisterFixedProbability(100).Tag("Pivot").Describe("Can modify an executable used by an enabled task; activation still depends on its trigger")

// importTask adds a scheduled task. A task becomes a node only when someone
// other than the machine's admin-equivalent principals can change it or
// write its action executables; otherwise the only thing it adds is that the
// machine runs code as the task's account, which becomes a direct edge.
func importTask(g *engine.Tx, machine engine.TxNode, scope MachineScope, task lm.RegisteredTask, admin adminEquivalent) {
	account := taskIdentity(g, machine, scope, task)
	var writers []windowssecurity.SID
	if account.Valid() {
		writers = taskActionWriters(task, admin)
	}
	controls := taskControls(task, admin)
	if len(writers) == 0 && len(controls) == 0 {
		if account.Valid() {
			g.EdgeBecause(machine, account, ad.EdgeAuthenticatesAs, Collected("scheduled task "+task.Name))
		}
		return
	}
	taskNode := g.AddNew(
		engine.IgnoreBlanks,
		activedirectory.Name, task.Name,
		activedirectory.Description, task.Definition.RegistrationInfo.Description,
		engine.Type, "ScheduledTask",
	)
	taskNode.ChildOf(machine)
	cause := Collected("scheduled task "+task.Name)
	g.EdgeBecause(machine, taskNode, EdgeHosts, cause)
	if account.Valid() {
		g.EdgeBecause(taskNode, account, ad.EdgeAuthenticatesAs, cause)
	}
	for _, sid := range writers {
		g.EdgeBecause(scope.Principal(sid), taskNode, EdgeTaskActionWrite, Collected("scheduled task "+task.Name+" action file permissions"))
	}
	for _, control := range controls {
		principal := scope.Principal(control.sid)
		for _, edge := range control.edges {
			g.EdgeBecause(principal, taskNode, edge, Collected("scheduled task "+task.Name+" permissions"))
		}
	}
}

// taskIdentity returns the account an enabled task runs as unattended, if
// any.
func taskIdentity(g *engine.Tx, machine engine.TxNode, scope MachineScope, task lm.RegisteredTask) engine.TxNode {
	if !task.Enabled || !task.Definition.Settings.Enabled {
		return engine.TxNode{}
	}
	p := task.Definition.Principal
	if p.LogonType != TASK_LOGON_PASSWORD && p.LogonType != TASK_LOGON_SERVICE_ACCOUNT && p.LogonType != TASK_LOGON_INTERACTIVE_TOKEN && p.LogonType != TASK_LOGON_S4U && p.LogonType != TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD {
		return engine.TxNode{}
	}
	var account engine.TxNode
	name := p.UserID
	switch strings.ToUpper(name) {
	case "SYSTEM", "NT AUTHORITY\\SYSTEM":
		if p.RunLevel != 1 {
			return engine.TxNode{}
		}
		account = scope.Principal(windowssecurity.SystemSID)
	case "LOCAL SERVICE", "NT AUTHORITY\\LOCAL SERVICE":
		account = scope.Principal(windowssecurity.LocalServiceSID)
	case "NETWORK SERVICE", "NT AUTHORITY\\NETWORK SERVICE":
		account = scope.Principal(windowssecurity.NetworkServiceSID)
	default:
		if sid, err := windowssecurity.ParseStringSID(name); err == nil {
			account = scope.Principal(sid)
		} else if domain, user, found := strings.Cut(name, `\`); found {
			if domain == "." {
				domain = machine.Node().Label()
			}
			if name := downLevelLogonName(domain, user); name != "" {
				account, _ = g.FindOrAdd(engine.DownLevelLogonName, engine.NV(name))
			}
		} else if strings.Contains(name, "@") {
			account, _ = g.FindOrAdd(engine.UserPrincipalName, engine.NV(name))
		}
	}
	return account
}

// taskActionWriters returns who besides the admin-equivalent principals can
// write a task's action executables.
func taskActionWriters(task lm.RegisteredTask, admin adminEquivalent) []windowssecurity.SID {
	var writers []windowssecurity.SID
	for _, action := range task.Definition.Actions {
		acl, err := engine.ParseACL(action.PathDACL)
		if err != nil || !plainAllowACL(acl) {
			continue
		}
		for _, ace := range acl.Entries {
			if ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE != 0 || admin(ace.SID) {
				continue
			}
			if ace.Mask&(engine.FILE_WRITE_DATA|engine.Mask(0x40000000|0x10000000)) != 0 {
				writers = append(writers, ace.SID)
			}
		}
	}
	return writers
}

type taskControl struct {
	sid   windowssecurity.SID
	edges []engine.Edge
}

// taskControls returns who besides the admin-equivalent principals and
// service accounts can change the task, and how.
func taskControls(task lm.RegisteredTask, admin adminEquivalent) []taskControl {
	if task.Definition.RegistrationInfo.SecurityDescriptor == "" {
		return nil
	}
	sd, err := engine.ParseSDDL(task.Definition.RegistrationInfo.SecurityDescriptor)
	if err != nil || !plainAllowACL(sd) {
		return nil
	}
	var controls []taskControl
	for _, entry := range sd.Entries {
		if admin(entry.SID) || entry.SID.Component(2) == 80 /* service account */ {
			continue
		}
		if entry.Type != engine.ACETYPE_ACCESS_ALLOWED || entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE != 0 {
			continue
		}
		var edges []engine.Edge
		if entry.Mask&engine.WRITE_DAC == engine.WRITE_DAC {
			edges = append(edges, activedirectory.EdgeWriteDACL)
		}
		if entry.Mask&engine.WRITE_OWNER == engine.WRITE_OWNER {
			edges = append(edges, activedirectory.EdgeTakeOwnership)
		}
		if entry.Mask&(engine.TASK_WRITE|engine.Mask(0x40000000)) != 0 {
			edges = append(edges, activedirectory.EdgeWriteAll)
		}
		if entry.Mask&engine.TASK_FULL_CONTROL == engine.TASK_FULL_CONTROL || entry.Mask&0x10000000 != 0 {
			edges = append(edges, activedirectory.EdgeGenericAll)
		}
		if len(edges) > 0 {
			controls = append(controls, taskControl{entry.SID, edges})
		}
	}
	return controls
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
