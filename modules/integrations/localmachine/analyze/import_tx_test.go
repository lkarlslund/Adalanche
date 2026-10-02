package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	adanalyze "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func syntheticMachine(name, localSID, domainSID string) lm.Info {
	info := benchmarkCollectorInfo()
	info.Machine.Name = name
	info.Machine.LocalSID = localSID
	info.Machine.IsDomainJoined = true
	info.Machine.ComputerDomainSID = domainSID
	info.Users = lm.Users{{Name: "alice", SID: localSID + "-1001", IsEnabled: true}}
	info.Groups = lm.Groups{{Name: "Administrators", SID: "S-1-5-32-544", Members: []lm.Member{
		{Name: name + `\alice`, SID: localSID + "-1001"},
	}}}
	return info
}

// One transaction per machine collection: local accounts referenced as group
// members are the accounts the collection listed, and every machine keeps its
// own builtin groups.
func TestMachineImportResolvesLocalPrincipalsInScope(t *testing.T) {
	g := engine.NewIndexedGraph()
	machines := map[string]*engine.Node{}
	for _, m := range []struct{ name, local, domain string }{
		{"HOST01", "S-1-5-21-111-222-333", "S-1-5-21-900-901-902-1101"},
		{"HOST02", "S-1-5-21-444-555-666", "S-1-5-21-900-901-902-1102"},
	} {
		machine, err := importMachine(g, syntheticMachine(m.name, m.local, m.domain))
		if err != nil {
			t.Fatal(err)
		}
		machines[m.name] = machine
		if machine.Type() != engine.NodeTypeMachine || machine.OneAttrString(engine.DataSource) != m.name {
			t.Errorf("%v: type %v, data source %q", m.name, machine.Type(), machine.OneAttrString(engine.DataSource))
		}
		if machine.OneAttr(adanalyze.DomainJoinedSID).IsNil() {
			t.Errorf("%v: domain joined SID missing", m.name)
		}

		computer, found := g.Find(activedirectory.ObjectSid, engine.NVSID(windowssecurity.MustParseStringSID(m.domain)))
		if !found {
			t.Fatalf("%v: computer account missing", m.name)
		}
		if machine.Parent() != computer {
			t.Errorf("%v: machine not under its computer account", m.name)
		}
		edges, _ := g.GetEdge(machine, computer)
		if !edges.IsSet(adanalyze.EdgeAuthenticatesAs) || !edges.IsSet(adanalyze.EdgeMachineAccount) {
			t.Errorf("%v: machine not linked to its computer account", m.name)
		}

		alice, _ := g.FindMulti(activedirectory.ObjectSid, engine.NVSID(windowssecurity.MustParseStringSID(m.local+"-1001")))
		if alice.Len() != 1 {
			t.Fatalf("%v: got %v nodes for the local account, want 1", m.name, alice.Len())
		}
		admins, found := g.FindAdjacentSID(windowssecurity.AdministratorsSID, machine)
		if !found {
			t.Fatalf("%v: Administrators missing", m.name)
		}
		if admins.Parent() != machine || alice.First().Parent() != machine {
			t.Errorf("%v: local principals not under the machine", m.name)
		}
		if edges, _ := g.GetEdge(alice.First(), admins); !edges.IsSet(activedirectory.EdgeMemberOfGroup) {
			t.Errorf("%v: local account not a member of Administrators", m.name)
		}
		if edges, _ := g.GetEdge(admins, machine); !edges.IsSet(EdgeLocalAdminRights) {
			t.Errorf("%v: Administrators has no admin rights on the machine", m.name)
		}
	}
	if admins, _ := g.FindMulti(activedirectory.ObjectSid, engine.NVSID(windowssecurity.AdministratorsSID)); admins.Len() != 2 {
		t.Errorf("got %v Administrators nodes, want one per machine", admins.Len())
	}
	if _, err := importMachine(g, syntheticMachine("HOST03", "S-1-5-21-777-888-999", "S-1-5-21-900-901-902-1101")); err == nil {
		t.Error("a second collection with the same domain SID was imported")
	}
}
