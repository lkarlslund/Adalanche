package analyze

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestTaskExecutablePermissions(t *testing.T) {
	user := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	for _, tc := range []struct {
		name                string
		enabled, deny, want bool
	}{
		{"enabled", true, false, true}, {"disabled", false, false, false}, {"deny-needs-token-evaluation", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := engine.NewIndexedGraph()
			machine := g.AddNew(engine.Type, "Machine", engine.Name, "synthetic", engine.DataSource, "synthetic")
			node := g.AddNew(engine.Type, "ScheduledTask", engine.Name, "task")
			aces := []engine.ACE{{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: user, Mask: engine.FILE_WRITE_DATA}}
			if tc.deny {
				aces = append(aces, engine.ACE{Type: engine.ACETYPE_ACCESS_DENIED, SID: user, Mask: engine.FILE_WRITE_DATA})
			}
			task := lm.RegisteredTask{Enabled: tc.enabled, Definition: lm.TaskDefinition{Settings: lm.TaskSettings{Enabled: tc.enabled}, Principal: lm.Principal{UserID: "SYSTEM", LogonType: TASK_LOGON_SERVICE_ACCOUNT, RunLevel: 1}, Actions: []lm.TaskAction{{PathDACL: serviceTestACL(aces...)}}}}
			importTaskExecution(g, machine, node, task)
			found := false
			g.IterateEdges(node, engine.In, func(source *engine.Node, edges engine.EdgeBitmap) bool {
				found = found || edges.IsSet(EdgeTaskActionWrite)
				return true
			})
			if found != tc.want {
				t.Fatalf("write edge=%v want %v", found, tc.want)
			}
		})
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
	n := g.AddNew(engine.Type, "Machine")
	info := lm.Info{Software: []lm.Software{{DisplayName: "sample", UninstallString: "secret command"}}, LoginInfos: []lm.LogonInfo{{Count: 100, LastSeen: time.Now().UTC()}}}
	if err := importLocalEvidence(n, info); err != nil {
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
