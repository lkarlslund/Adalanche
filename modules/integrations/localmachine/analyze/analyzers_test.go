package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Machines are linked to the update server they name, by DNS name or else
// by plain name, ignoring case; an address cannot be linked.
func TestLinkSCCMProcessorLinksUpdateServers(t *testing.T) {
	g := engine.NewIndexedGraph()
	machine := func(values ...any) *engine.Node {
		return enginetest.AddNew(g, append([]any{engine.Type, engine.NV("Machine")}, values...)...)
	}
	server := machine(engine.Name, "SRV01", DNSHostname, "srv01.example.org")
	byDNSName := machine(engine.Name, "WS01", WUServer, "SRV01.EXAMPLE.ORG")
	byName := machine(engine.Name, "WS02", SCCMServer, "srv01")
	byAddress := machine(engine.Name, "WS03", WUServer, "10.0.0.1")

	runTx(g, LinkSCCMProcessor)

	for name, client := range map[string]*engine.Node{"DNS name": byDNSName, "name": byName} {
		if edges, _ := g.GetEdge(server, client); !edges.IsSet(EdgeControlsUpdates) {
			t.Errorf("server named by %v is not linked", name)
		}
	}
	if edges, _ := g.GetEdge(server, byAddress); edges.IsSet(EdgeControlsUpdates) {
		t.Error("server named by address was linked")
	}
}

// Local users and groups go under the machine of their collection whose
// local SID they share.
func TestLinkLocalAccountsToMachines(t *testing.T) {
	g := engine.NewIndexedGraph()
	localSID := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3")
	machine := enginetest.AddNew(g, engine.Type, engine.NV("Machine"), engine.DataSource, "one",
		LocalMachineSID, engine.NV(localSID))
	account := func(nodeType engine.NodeType, source, sid string) *engine.Node {
		return enginetest.AddNew(g, engine.Type, nodeType.ValueString(), engine.DataSource, source,
			engine.ObjectSid, engine.NV(windowssecurity.MustParseStringSID(sid)))
	}
	user := account(engine.NodeTypeUser, "one", "S-1-5-21-1-2-3-1001")
	group := account(engine.NodeTypeGroup, "one", "S-1-5-21-1-2-3-513")
	otherCollection := account(engine.NodeTypeUser, "two", "S-1-5-21-1-2-3-1002")
	otherMachine := account(engine.NodeTypeUser, "one", "S-1-5-21-9-9-9-1001")

	runTx(g, linkLocalAccountsToMachines)

	for name, n := range map[string]*engine.Node{"user": user, "group": group} {
		if n.Parent() != machine {
			t.Errorf("local %v is not under its machine", name)
		}
	}
	for name, n := range map[string]*engine.Node{"another collection's user": otherCollection, "another machine's user": otherMachine} {
		if n.Parent() == machine {
			t.Errorf("%v was put under the machine", name)
		}
	}
}

// A domain's Everyone and Authenticated Users are members of the same groups
// on machines joined to the domain, though they share the SID.
func TestDomainGroupsAreMembersOnJoinedMachines(t *testing.T) {
	g := engine.NewIndexedGraph()
	joined := windowssecurity.MustParseStringSID("S-1-5-21-900-901-902-1101")
	domain := func(sid windowssecurity.SID) *engine.Node {
		return enginetest.AddNew(g, engine.ObjectSid, engine.NV(sid), engine.DomainContext, "DC=example,DC=com", engine.DataSource, "EXAMPLE")
	}
	domainEveryone, domainUsers := domain(windowssecurity.EveryoneSID), domain(windowssecurity.AuthenticatedUsersSID)
	enginetest.AddNew(g, engine.Type, engine.NodeTypeComputer.ValueString(), engine.ObjectSid, engine.NV(joined), engine.DomainContext, "DC=example,DC=com", engine.DataSource, "EXAMPLE")
	machine := enginetest.AddNew(g, engine.Type, engine.NV("Machine"), attrs.DomainJoinedSID, engine.NV(joined), engine.DataSource, "HOST01")
	workgroup := enginetest.AddNew(g, engine.Type, engine.NV("Machine"), engine.DataSource, "HOST02")
	local := func(m *engine.Node, sid windowssecurity.SID) *engine.Node {
		n := enginetest.AddNew(g, engine.ObjectSid, engine.NV(sid), engine.DataSource, m.OneAttr(engine.DataSource))
		enginetest.ChildOf(g, n, m)
		return n
	}
	localEveryone, localUsers := local(machine, windowssecurity.EveryoneSID), local(machine, windowssecurity.AuthenticatedUsersSID)
	workgroupUsers := local(workgroup, windowssecurity.AuthenticatedUsersSID)

	runTx(g, linkDomainGroupsToMachines)

	for _, pair := range [][2]*engine.Node{{domainEveryone, localEveryone}, {domainUsers, localUsers}} {
		if edges, _ := g.GetEdge(pair[0], pair[1]); !edges.IsSet(activedirectory.EdgeMemberOfGroup) {
			t.Errorf("the domain's %v is not a member on the joined machine", pair[0].SID())
		}
	}
	if edges, _ := g.GetEdge(domainUsers, workgroupUsers); edges.IsSet(activedirectory.EdgeMemberOfGroup) {
		t.Error("a machine that is not joined got the domain's members")
	}
}
