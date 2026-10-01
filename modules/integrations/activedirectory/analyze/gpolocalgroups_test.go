package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
)

func TestGPOparseGroupsFollowsPreferenceActions(t *testing.T) {
	xml := `<Groups>
	<Group name="Update"><Properties action="U" groupSid="S-1-5-32-544"><Members><Member name="A" action="ADD" sid=""/><Member name="B" action="REMOVE" sid=""/></Members></Properties></Group>
	<Group name="Default"><Properties groupSid="S-1-5-32-555"><Members><Member name="C" action="add" sid=""/></Members></Properties></Group>
	<Group name="Replace"><Properties action="R" groupSid="S-1-5-32-562"><Members><Member name="D" action="ADD" sid=""/></Members></Properties></Group>
	<Group name="Create"><Properties action="C" groupSid="S-1-5-32-544"><Members><Member name="E" action="ADD" sid=""/></Members></Properties></Group>
	<Group name="Delete"><Properties action="D" groupSid="S-1-5-32-544"><Members><Member name="F" action="ADD" sid=""/></Members></Properties></Group>
	<Group name="By name"><Properties action="U" groupName="Administrators (built-in)"><Members><Member name="G" action="ADD" sid=""/></Members></Properties></Group>
	<Group name="Other group"><Properties action="U" groupSid="S-1-5-32-5440"><Members><Member name="H" action="ADD" sid=""/></Members></Properties></Group>
	<Group name="Current user"><Properties action="U" groupSid="S-1-5-32-544" userAction="ADD"/></Group>
	<Group name="Current user excluded"><Properties action="U" groupSid="S-1-5-32-544" userAction="ADD" removeAccounts="1"/></Group>
</Groups>`
	got := map[string]string{}
	currentUser := 0
	for _, p := range GPOparseGroups(xml) {
		if p.CurrentUser {
			currentUser++
			continue
		}
		got[p.MemberName] = p.GroupSID
	}
	want := map[string]string{"A": "S-1-5-32-544", "C": "S-1-5-32-555", "D": "S-1-5-32-562", "G": "S-1-5-32-544"}
	if len(got) != len(want) {
		t.Fatalf("got members %v, want %v", got, want)
	}
	for name, sid := range want {
		if got[name] != sid {
			t.Errorf("member %s: got group %q, want %q", name, got[name], sid)
		}
	}
	if currentUser != 1 {
		t.Errorf("got %d current-user grants, want 1", currentUser)
	}
}

func TestExpandComputerVariables(t *testing.T) {
	for _, tt := range []struct {
		in, want string
		ok       bool
	}{
		{`%ComputerName%_Admins`, `WS01_Admins`, true},
		{`%DOMAINNAME%\LA_%computername%`, `EXAMPLE\LA_WS01`, true},
		{`Helpdesk`, `Helpdesk`, true},
		{`%LogonDomain%\%LogonUser%`, ``, false},
		{`%ComputerName%_%MacAddress%`, ``, false},
	} {
		got, ok := expandComputerVariables(tt.in, "WS01", "EXAMPLE")
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("%s: got %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestGPOLocalGroupMembersResolveByNameAndPerMachine(t *testing.T) {
	computerSID := mustSID(t, "S-1-5-21-111-222-333-1001")
	gpo := engine.NewNode(engine.Name, "Local Admins", engine.DistinguishedName, "CN={66666666-6666-6666-6666-666666666666},CN=Policies,CN=System,DC=example,DC=com", engine.DomainContext, "DC=example,DC=com")
	for _, v := range []string{
		`S-1-5-32-544|EXAMPLE\%ComputerName%_Admins`,
		`S-1-5-32-555|%DomainName%\RDP_%ComputerName%`,
		`S-1-5-32-544|Helpdesk`,
		`S-1-5-32-544|%<ComputerName>%_Admins`,
		`S-1-5-32-544|%LogonUser%`,
		`S-1-5-32-544|EXAMPLE\Nobody`,
	} {
		gpo.Add(GPOLocalGroupMember, engine.NV(v))
	}
	crossref := engine.NewNode(engine.ObjectClass, "crossRef", NCName, "DC=example,DC=com", NetBIOSName, "EXAMPLE")
	computer := engine.NewNode(engine.Type, engine.NodeTypeComputer.ValueString(), engine.ObjectSid, computerSID, engine.SAMAccountName, "WS01$", engine.DownLevelLogonName, `EXAMPLE\WS01$`, engine.DomainContext, "DC=example,DC=com")
	machine := engine.NewNode(engine.Name, "WS01", engine.Type, ObjectTypeMachine.ValueString(), DomainJoinedSID, computerSID, attrs.DomainJoinedSID, computerSID)
	admins := engine.NewNode(engine.Name, "WS01_Admins", engine.Type, engine.NodeTypeGroup.ValueString(), engine.SAMAccountName, "WS01_Admins", engine.DownLevelLogonName, `EXAMPLE\WS01_Admins`)
	rdp := engine.NewNode(engine.Name, "RDP_WS01", engine.Type, engine.NodeTypeGroup.ValueString(), engine.SAMAccountName, "RDP_WS01", engine.DownLevelLogonName, `EXAMPLE\RDP_WS01`)
	helpdesk := engine.NewNode(engine.Name, "Helpdesk", engine.Type, engine.NodeTypeGroup.ValueString(), engine.SAMAccountName, "Helpdesk", engine.DownLevelLogonName, `EXAMPLE\Helpdesk`)

	graph := newADTestGraph(gpo, crossref, computer, machine, admins, rdp, helpdesk)
	graph.EdgeTo(gpo, machine, activedirectory.EdgeAffectedByGPO)
	resolveGPOLocalGroupMembers(graph)

	requireEdgeSet(t, graph, admins, machine, activedirectory.EdgeLocalAdminRights)
	requireEdgeSet(t, graph, rdp, machine, activedirectory.EdgeLocalRDPRights)
	requireEdgeSet(t, graph, helpdesk, gpo, activedirectory.EdgeLocalAdminRights)
	requireNoEdgeSet(t, graph, admins, gpo, activedirectory.EdgeLocalAdminRights)

	// The escaped and the unknown names stay visible as unresolved principals.
	for _, name := range []string{`%ComputerName%_Admins`, `EXAMPLE\Nobody`} {
		placeholder, found := graph.Find(engine.SAMAccountName, engine.NV(name))
		if !found {
			t.Fatalf("no placeholder for %s", name)
		}
		requireEdgeSet(t, graph, placeholder, gpo, activedirectory.EdgeLocalAdminRights)
	}
	if _, found := graph.Find(engine.SAMAccountName, engine.NV(`%LogonUser%`)); found {
		t.Fatal("a user-dependent variable must not become a principal")
	}
}
