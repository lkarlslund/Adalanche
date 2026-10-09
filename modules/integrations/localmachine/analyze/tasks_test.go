package analyze

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	ad "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func systemTask(enabled bool, actionACL []byte) lm.RegisteredTask {
	return lm.RegisteredTask{Name: "task", Enabled: enabled, Definition: lm.TaskDefinition{Settings: lm.TaskSettings{Enabled: enabled}, Principal: lm.Principal{UserID: "SYSTEM", LogonType: TASK_LOGON_SERVICE_ACCOUNT, RunLevel: 1}, Actions: []lm.TaskAction{{PathDACL: actionACL}}}}
}

// importTestTask imports a task on a synthetic machine and returns the
// machine and the task node, if one was made.
func importTestTask(task lm.RegisteredTask) (*engine.IndexedGraph, *engine.Node, *engine.Node) {
	g := engine.NewIndexedGraph()
	machine := enginetest.AddNew(g, engine.Type, "Machine", engine.Name, "synthetic", engine.DataSource, "synthetic")
	runTx(g, func(tx *engine.Tx) {
		importTask(tx, tx.Node(machine), MachineScope{tx: tx, machine: tx.Node(machine)}, task, localAdministratorSID)
	})
	var taskNode *engine.Node
	g.Iterate(func(n *engine.Node) bool {
		if n.OneAttrString(engine.Type) == "ScheduledTask" {
			taskNode = n
		}
		return true
	})
	return g, machine, taskNode
}

func TestTaskExecutablePermissions(t *testing.T) {
	user := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	for _, tc := range []struct {
		name                string
		enabled, deny, want bool
	}{
		{"enabled", true, false, true}, {"disabled", false, false, false}, {"deny-needs-token-evaluation", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aces := []engine.ACE{{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: user, Mask: engine.FILE_WRITE_DATA}}
			if tc.deny {
				aces = append(aces, engine.ACE{Type: engine.ACETYPE_ACCESS_DENIED, SID: user, Mask: engine.FILE_WRITE_DATA})
			}
			g, _, node := importTestTask(systemTask(tc.enabled, serviceTestACL(aces...)))
			found := false
			if node != nil {
				g.IterateEdges(node, engine.In, func(source *engine.Node, edges engine.EdgeBitmap) bool {
					found = found || edges.IsSet(EdgeTaskActionWrite)
					return true
				})
			}
			if found != tc.want {
				t.Fatalf("write edge=%v want %v", found, tc.want)
			}
		})
	}
}

// A task only the machine's admins can change is not a node; the machine
// runs code as its account, which becomes a direct edge.
func TestAdminOnlyTaskBecomesAnEdgeFromTheMachine(t *testing.T) {
	adminOnly := serviceTestACL(engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: windowssecurity.AdministratorsSID, Mask: engine.FILE_WRITE_DATA})
	g, machine, node := importTestTask(systemTask(true, adminOnly))
	if node != nil {
		t.Fatal("an admin-only task became a node")
	}
	runsAsSystem := false
	g.IterateEdges(machine, engine.Out, func(target *engine.Node, edges engine.EdgeBitmap) bool {
		runsAsSystem = runsAsSystem || (target.SID() == windowssecurity.SystemSID && edges.IsSet(ad.EdgeAuthenticatesAs))
		return true
	})
	if !runsAsSystem {
		t.Fatal("the machine does not authenticate as the task's account")
	}
}

func TestLocalDenyIncludesNestedLocalGroups(t *testing.T) {
	info := lm.Info{Groups: lm.Groups{{SID: "outer", Members: []lm.Member{{SID: "inner"}}}, {SID: "inner", Members: []lm.Member{{SID: "user"}}}}, Privileges: lm.Privileges{{Name: "SeDenyNetworkLogonRight", AssignedSIDs: []string{"outer"}}}}
	if !locallyDeniedLogon(info, "user", "SeDenyNetworkLogonRight") {
		t.Fatal("nested deny ignored")
	}
	if locallyDeniedLogon(info, "user", "SeDenyRemoteInteractiveLogonRight") {
		t.Fatal("wrong logon type denied")
	}
}

func TestLocalEvidenceOmitsCommandsAndRetainsCounts(t *testing.T) {
	g := engine.NewIndexedGraph()
	n := enginetest.AddNew(g, engine.Type, "Machine")
	info := lm.Info{Software: []lm.Software{{DisplayName: "sample", UninstallString: "secret command"}}, LoginInfos: []lm.LogonInfo{{Count: 100, LastSeen: time.Now().UTC()}}}
	var err error
	runTx(g, func(tx *engine.Tx) { err = importLocalEvidence(tx.Node(n), info) })
	if err != nil {
		t.Fatal(err)
	}
	var got LocalEvidenceCapture
	if err := json.Unmarshal([]byte(n.OneAttrString(LocalEvidence)), &got); err != nil {
		t.Fatal(err)
	}
	if got.Software[0].UninstallString != "" || got.Logins[0].Count != 100 || got.Logins[0].LastSeen.IsZero() {
		t.Fatalf("unexpected evidence: %+v", got)
	}
	if info.Software[0].UninstallString == "" {
		t.Fatal("modified caller data")
	}
}
