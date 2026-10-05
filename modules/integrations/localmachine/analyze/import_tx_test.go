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
	// A collection claiming an account another collection claims is a
	// machine of its own; which one is current is decided before the merge.
	if _, err := importMachine(g, syntheticMachine("HOST03", "S-1-5-21-777-888-999", "S-1-5-21-900-901-902-1101")); err != nil {
		t.Fatal(err)
	}
	if machines := adanalyze.MachinesForComputer(g, windowssecurity.MustParseStringSID("S-1-5-21-900-901-902-1101")); len(machines) != 2 {
		t.Errorf("got %v machines for the shared account, want 2", len(machines))
	}
}

// Local group edges record the machine's collection as their cause, which
// leads to the machine.
func TestLocalGroupEdgesRecordTheCollection(t *testing.T) {
	g := engine.NewIndexedGraph()
	machine, err := importMachine(g, syntheticMachine("HOST01", "S-1-5-21-111-222-333", "S-1-5-21-900-901-902-1101"))
	if err != nil {
		t.Fatal(err)
	}
	var admins, alice *engine.Node
	g.Iterate(func(n *engine.Node) bool {
		switch n.SID().String() {
		case "S-1-5-32-544":
			if n.Parent() == machine {
				admins = n
			}
		case "S-1-5-21-111-222-333-1001":
			alice = n
		}
		return true
	})
	if admins == nil || alice == nil {
		t.Fatal("local nodes missing")
	}
	for _, c := range []struct {
		from, to *engine.Node
		edge     engine.Edge
	}{{admins, machine, EdgeLocalAdminRights}, {alice, admins, activedirectory.EdgeMemberOfGroup}} {
		found := false
		for _, s := range g.EdgeSources(c.from, c.to) {
			found = found || (s.Edge == c.edge && s.Source.Kind == SourceCollection && s.Source.Origin(c.from, c.to) == machine && s.Source.Detail == "local group Administrators")
		}
		if !found {
			t.Errorf("%v to %v: %v has no collection cause", c.from.Label(), c.to.Label(), c.edge.String())
		}
	}
}

// A machine's own principals (built-in SIDs, its local accounts) are placed
// under it; domain accounts are not.
func TestMachinePrincipalsAreUnderTheMachine(t *testing.T) {
	info := syntheticMachine("HOST01", "S-1-5-21-111-222-333", "S-1-5-21-900-901-902-1101")
	info.Privileges = append(info.Privileges, lm.Privilege{Name: "SeDebugPrivilege", AssignedSIDs: []string{
		"S-1-5-18", "S-1-5-21-111-222-333-1005", "S-1-5-21-900-901-902-1105",
	}})
	g := engine.NewIndexedGraph()
	machine, err := importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	parents := map[string]*engine.Node{}
	g.Iterate(func(n *engine.Node) bool {
		parents[n.SID().String()] = n.Parent()
		return true
	})
	for _, sid := range []string{"S-1-5-18", "S-1-5-21-111-222-333-1005"} {
		if parents[sid] != machine {
			t.Errorf("%v is not under the machine", sid)
		}
	}
	if parents["S-1-5-21-900-901-902-1105"] == machine {
		t.Error("a domain account was put under the machine")
	}
}
