package analyze

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func assessment(t *testing.T, categories map[string][]map[string]any) *lm.Assessment {
	t.Helper()
	cats := map[string]lm.AssessmentCapture{}
	for name, records := range categories {
		var raws []json.RawMessage
		for _, r := range records {
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			raws = append(raws, raw)
		}
		c := lm.AssessmentCapture{Records: raws}
		c.Result.Status = "collected"
		cats[name] = c
	}
	return &lm.Assessment{Version: lm.AssessmentVersion, Captured: time.Now().UTC(), Categories: cats}
}

func TestImportHardening(t *testing.T) {
	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01")
	enginetest.Add(g, machine)
	a := assessment(t, map[string][]map[string]any{
		"smb-server":                 {{"RequireSecuritySignature": false, "EnableSMB1Protocol": true}},
		"authentication-policy":      {{"Path": `...\Lsa`, "LmCompatibilityLevel": 2}},
		"lsa-protection-runtime":     {{"Id": 12}},
		"password-management-policy": {{"Kind": "active-policy-source", "ManagedAccountName": "localadm"}},
	})
	runTx(g, func(tx *engine.Tx) { importHardening(tx, tx.Node(machine), a) })

	if v, ok := machine.AttrBool(SMBSigningRequired); !ok || v {
		t.Error("SMB signing should be recorded as not required")
	}
	if !machine.HasTag("smb_signing_not_required") || !machine.HasTag("smb1_enabled") ||
		!machine.HasTag("weak_ntlm_authentication") || !machine.HasTag("lsa_protection") || !machine.HasTag("laps_enabled") {
		t.Error("missing a hardening tag")
	}
	if v, ok := machine.AttrInt(LMCompatibilityLevel); !ok || v != 2 {
		t.Errorf("LmCompatibilityLevel %v", v)
	}
	if machine.OneAttrString(LAPSManagedAccount) != "localadm" {
		t.Error("LAPS managed account not recorded")
	}
}

// LSA protection with no runtime event is recorded as not running; an
// uncollected category sets nothing.
func TestImportHardeningLSAStates(t *testing.T) {
	for _, tt := range []struct {
		name      string
		collected bool
		records   []map[string]any
		wantAttr  bool
		wantValue bool
	}{
		{"running", true, []map[string]any{{"Id": 12}}, true, true},
		{"not running", true, nil, true, false},
		{"not collected", false, nil, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := engine.NewIndexedGraph()
			machine := engine.NewNode(engine.Name, "WS01")
			enginetest.Add(g, machine)
			a := &lm.Assessment{Version: lm.AssessmentVersion, Categories: map[string]lm.AssessmentCapture{}}
			if tt.collected {
				a = assessment(t, map[string][]map[string]any{"lsa-protection-runtime": tt.records})
			}
			runTx(g, func(tx *engine.Tx) { importLSAProtection(tx.Node(machine), a) })
			v, ok := machine.AttrBool(LSAProtectionRunning)
			if ok != tt.wantAttr || v != tt.wantValue {
				t.Errorf("got (%v,%v), want (%v,%v)", v, ok, tt.wantValue, tt.wantAttr)
			}
		})
	}
}

func TestAlwaysInstallElevatedEdge(t *testing.T) {
	userSID := "S-1-5-21-1-2-3-1001"
	for _, machineOn := range []bool{true, false} {
		g := engine.NewIndexedGraph()
		machine := engine.NewNode(engine.Name, "WS01", engine.DistinguishedName, "WS01")
		enginetest.Add(g, machine)
		if machineOn {
			runTx(g, func(tx *engine.Tx) { tx.Node(machine).Set(InstallerElevatedMachine, engine.NV(true)) })
		}
		a := assessment(t, map[string][]map[string]any{
			"user-installer-policy": {{"UserSID": userSID, "AlwaysInstallElevated": 1}},
		})
		runTx(g, func(tx *engine.Tx) { importHardening(tx, tx.Node(machine), a) })

		user, found := g.FindAdjacentSID(windowssecurity.MustParseStringSID(userSID), machine)
		edged := false
		if found {
			edges, _ := g.GetEdge(user, machine)
			edged = edges.IsSet(EdgeAlwaysInstallElevated)
		}
		if edged != machineOn {
			t.Errorf("machineOn=%v: edge present=%v", machineOn, edged)
		}
	}
}
