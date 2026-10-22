package analyze

import (
	"slices"
	"strings"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"golang.org/x/text/encoding/unicode"
)

const gptTmplRights = "[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\nSeMachineAccountPrivilege = *S-1-5-11\r\nSeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551, EXAMPLE\\backupsvc\r\nSeDebugPrivilege =\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\n"

func TestGPOparsePrivilegeRights(t *testing.T) {
	utf16, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewEncoder().String(gptTmplRights)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"UTF-16": utf16, "plain": gptTmplRights} {
		var got []string
		for _, r := range GPOparsePrivilegeRights(raw) {
			got = append(got, r.value())
		}
		slices.Sort(got)
		want := []string{
			"SeBackupPrivilege|*S-1-5-32-544,*S-1-5-32-551,EXAMPLE\\backupsvc",
			"SeDebugPrivilege|", // assigned to no one, which still replaces
			"SeMachineAccountPrivilege|*S-1-5-11",
		}
		if !slices.Equal(got, want) {
			t.Errorf("%v: %q, want %q", name, got, want)
		}
	}
}

// Site, domain, then OUs from the top; within a scope its gPLink in order;
// enforced links after all others, the higher scopes last.
func TestGPOApplicationOrder(t *testing.T) {
	gpo := map[string]*engine.Node{}
	for _, name := range []string{"ou", "ou2", "parentou", "domain1", "domain2", "site", "enforcedDomain", "enforcedOU", "twice"} {
		gpo[name] = engine.NewNode(engine.Name, name)
	}
	links := []gpoLink{
		{gpo["ou"], 0, 0, false},
		{gpo["ou2"], 0, 1, false},
		{gpo["enforcedOU"], 0, 2, true},
		{gpo["twice"], 0, 3, false},
		{gpo["parentou"], 1, 0, false},
		{gpo["domain1"], 2, 0, false},
		{gpo["domain2"], 2, 1, false},
		{gpo["enforcedDomain"], 2, 2, true},
		{gpo["twice"], 2, 3, false},
		{gpo["site"], 3, 0, false},
	}
	var got []string
	for _, n := range gpoApplicationOrder(links) {
		got = append(got, n.Label())
	}
	want := []string{"site", "domain1", "domain2", "parentou", "ou", "ou2", "twice", "enforcedOU", "enforcedDomain"}
	if !slices.Equal(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}
}

// rightsGraph is a domain with GPOs assigning rights, applied in the order
// given to a machine.
func rightsGraph(t *testing.T, collected bool, gpos ...[]string) (*engine.IndexedGraph, *engine.Node) {
	t.Helper()
	nodes := []*engine.Node{
		engine.NewNode(engine.Name, "Authenticated Users", engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-11")), engine.DomainContext, "DC=example,DC=com"),
		engine.NewNode(engine.Name, "Administrators", engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-32-544")), engine.DomainContext, "DC=example,DC=com"),
		engine.NewNode(engine.Name, "Users", engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-32-545")), engine.DomainContext, "DC=example,DC=com"),
	}
	var order engine.AttributeValues
	for i, rights := range gpos {
		dn := "CN={" + strings.Repeat(string(rune('A'+i)), 8) + "},CN=Policies,CN=System,DC=example,DC=com"
		var values engine.AttributeValues
		for _, r := range rights {
			values = append(values, engine.NV(r))
		}
		nodes = append(nodes, engine.NewNode(engine.Name, "GPO"+string(rune('A'+i)), engine.DistinguishedName, dn, engine.DomainContext, "DC=example,DC=com",
			GPOUserRight, values))
		order = append(order, engine.NV(dn))
	}
	init := []any{engine.Name, "DC01", engine.Type, ObjectTypeMachine.ValueString(), GPOApplicationOrder, order}
	if collected {
		init = append(init, localmachine.CollectedAt, engine.NV("2026-01-01"))
	}
	machine := engine.NewNode(init...)
	graph := newADTestGraph(append(nodes, machine)...)
	runTx(graph, resolveGPOUserRights)
	return graph, machine
}

func holders(graph *engine.IndexedGraph, machine *engine.Node, edge engine.Edge) []string {
	var names []string
	graph.IterateEdges(machine, engine.In, func(from *engine.Node, eb engine.EdgeBitmap) bool {
		if eb.IsSet(edge) {
			names = append(names, from.Label())
		}
		return true
	})
	slices.Sort(names)
	return names
}

// A right's assignment is the last applied GPO's that assigns it, and deny
// rights take logon rights away.
func TestGPOUserRights(t *testing.T) {
	graph, machine := rightsGraph(t, false,
		[]string{"SeMachineAccountPrivilege|*S-1-5-11", "SeBackupPrivilege|*S-1-5-32-544"},
		[]string{"SeMachineAccountPrivilege|*S-1-5-32-544"}, // applied later: replaces Authenticated Users
		[]string{"SeNetworkLogonRight|*S-1-5-11,*S-1-5-32-545", "SeDenyNetworkLogonRight|*S-1-5-32-545"},
	)
	for edge, want := range map[engine.Edge][]string{
		activedirectory.EdgeSeMachineAccountPrivilege: {"Administrators"},
		activedirectory.EdgeSeBackupPrivilege:         {"Administrators"},
		activedirectory.EdgeSeNetworkLogonRight:       {"Authenticated Users"},
	} {
		if got := holders(graph, machine, edge); !slices.Equal(got, want) {
			t.Errorf("%v: %v, want %v", edge.String(), got, want)
		}
	}
	// The order decides: reversed, Authenticated Users wins.
	graph, machine = rightsGraph(t, false,
		[]string{"SeMachineAccountPrivilege|*S-1-5-32-544"},
		[]string{"SeMachineAccountPrivilege|*S-1-5-11"},
	)
	if got := holders(graph, machine, activedirectory.EdgeSeMachineAccountPrivilege); !slices.Equal(got, []string{"Authenticated Users"}) {
		t.Errorf("reversed: %v", got)
	}

	// A collected machine keeps the rights its collection lists.
	graph, machine = rightsGraph(t, true, []string{"SeMachineAccountPrivilege|*S-1-5-11"})
	if got := holders(graph, machine, activedirectory.EdgeSeMachineAccountPrivilege); len(got) != 0 {
		t.Errorf("collected machine got %v from GPOs", got)
	}
}

// domainNodes are what the analysis knows a domain by: its object (with the
// quota, when given), its crossRef, and its Domain Computers group.
func domainNodes(t *testing.T, domainDN, quota string, extra ...any) []*engine.Node {
	t.Helper()
	init := []any{engine.Name, "example", engine.Type, engine.NodeTypeDomainDNS.ValueString(), engine.ObjectClass, "domainDNS",
		engine.DistinguishedName, domainDN, engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-21-1-2-3"))}
	if quota != "" {
		init = append(init, engine.NewAttribute("ms-DS-MachineAccountQuota"), engine.NV(quota))
	}
	return []*engine.Node{
		engine.NewNode(append(init, extra...)...),
		engine.NewNode(engine.ObjectClass, "crossRef", NCName, domainDN, NetBIOSName, "EXAMPLE", DNSRoot, "example.com"),
		engine.NewNode(engine.Name, "Domain Computers", engine.Type, engine.NodeTypeGroup.ValueString(), engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-21-1-2-3-515")),
			engine.DomainContext, domainDN),
	}
}

// GPO targeting records the order a domain controller applies its GPOs in,
// and the last GPO assigning SeMachineAccountPrivilege decides who holds it:
// the OU's GPO over the domain's, an enforced domain link over both.
func TestMachineAccountPrivilegeFollowsGPOPrecedence(t *testing.T) {
	const domainDN = "DC=example,DC=test"
	for _, enforced := range []bool{false, true} {
		sd := engine.NV(securityDescriptorWithACEs(
			allowACE(windowssecurity.AuthenticatedUsersSID, engine.RIGHT_DS_READ_PROPERTY, uuid.Nil),
			allowACE(windowssecurity.AuthenticatedUsersSID, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightApplyGroupPolicy),
		))
		gpo := func(name string, rights ...string) *engine.Node {
			var values engine.AttributeValues
			for _, r := range rights {
				values = append(values, engine.NV(r))
			}
			return engine.NewNode(engine.Name, name, engine.Type, engine.NodeTypeGroupPolicyContainer.ValueString(),
				engine.DistinguishedName, "CN="+name+",CN=Policies,CN=System,"+domainDN, engine.DomainContext, domainDN, engine.NTSecurityDescriptor, sd,
				GPOUserRight, values)
		}
		site := gpo("site-gpo", "SeMachineAccountPrivilege|*S-1-5-32-548")
		low := gpo("domain-low", "SeMachineAccountPrivilege|*S-1-5-32-545")
		high := gpo("domain-high")
		ouGPO := gpo("dc-policy", "SeMachineAccountPrivilege|*S-1-5-11")
		enforcedGPO := gpo("domain-enforced", "SeMachineAccountPrivilege|*S-1-5-32-544")
		domainLinks := "[LDAP://" + low.DN() + ";0][LDAP://" + high.DN() + ";0]"
		if enforced {
			domainLinks += "[LDAP://" + enforcedGPO.DN() + ";2]"
		}
		domainParts := domainNodes(t, domainDN, "10", activedirectory.GPLink, domainLinks)
		domain := domainParts[0]
		ou := engine.NewNode(engine.DistinguishedName, "OU=Domain Controllers,"+domainDN, activedirectory.GPLink, "[LDAP://"+ouGPO.DN()+";0]")
		siteNode := engine.NewNode(engine.Name, "hq", engine.ObjectClass, "site", engine.DistinguishedName, "CN=hq,CN=Sites,CN=Configuration,"+domainDN,
			activedirectory.GPLink, "[LDAP://"+site.DN()+";0]")
		computerSID := mustSID(t, "S-1-5-21-1-2-3-1000")
		computer := engine.NewNode(engine.Type, engine.NodeTypeComputer.ValueString(), engine.ObjectSid, engine.NV(computerSID),
			engine.DistinguishedName, "CN=DC01,OU=Domain Controllers,"+domainDN, engine.DomainContext, domainDN,
			activedirectory.UserAccountControl, engine.NV(int64(0x2000)))
		machine := engine.NewNode(engine.Name, "DC01", engine.Type, ObjectTypeMachine.ValueString(), DomainJoinedSID, engine.NV(computerSID), attrs.DomainJoinedSID, engine.NV(computerSID))
		principal := func(name, sid string) *engine.Node {
			return engine.NewNode(engine.Name, name, engine.ObjectSid, engine.NV(mustSID(t, sid)), engine.DomainContext, domainDN)
		}
		authenticated := principal("Authenticated Users", "S-1-5-11")
		admins := principal("Administrators", "S-1-5-32-544")
		users := principal("Users", "S-1-5-32-545")
		accountOps := principal("Account Operators", "S-1-5-32-548")

		graph := newADTestGraph(append(domainParts, site, low, high, ouGPO, enforcedGPO, ou, siteNode, computer, machine, authenticated, admins, users, accountOps)...)
		enginetest.ChildOf(graph, computer, ou)
		enginetest.ChildOf(graph, ou, domain)
		runTx(graph, addMachinesAffectedByGPO)
		runTx(graph, resolveGPOUserRights)

		var order []string
		machine.Attr(GPOApplicationOrder).Iterate(func(v engine.AttributeValue) bool {
			name, _, _ := strings.Cut(strings.TrimPrefix(v.String(), "CN="), ",")
			order = append(order, name)
			return true
		})
		wantOrder := []string{"site-gpo", "domain-low", "domain-high", "dc-policy"}
		want := "Authenticated Users"
		if enforced {
			wantOrder = append(wantOrder, "domain-enforced")
			want = "Administrators"
		}
		if !slices.Equal(order, wantOrder) {
			t.Errorf("enforced %v: order %v, want %v", enforced, order, wantOrder)
		}
		if got := holders(graph, machine, activedirectory.EdgeSeMachineAccountPrivilege); !slices.Equal(got, []string{want}) {
			t.Errorf("enforced %v: SeMachineAccountPrivilege held by %v, want %v", enforced, got, want)
		}
	}
}

// With the schema in the dump, the possible superiors of the computer class
// decide where computers can be created: inherited from its superclasses and
// auxiliary classes, and in subclasses of those, but not in a computer or a
// group, whatever the node's type says. Without it, the fallback types do.
func TestCanContain(t *testing.T) {
	values := func(names ...string) engine.AttributeValues {
		var v engine.AttributeValues
		for _, n := range names {
			v = append(v, engine.NV(n))
		}
		return v
	}
	class := func(name string, attrs ...any) *engine.Node {
		return engine.NewNode(append([]any{engine.Name, name, engine.Type, engine.NodeTypeClassSchema.ValueString(),
			engine.DistinguishedName, "CN=" + name + ",CN=Schema,CN=Configuration,DC=example,DC=com",
			engine.ObjectClass, values("top", "classSchema"), activedirectory.LDAPDisplayName, name}, attrs...)...)
	}
	schema := []*engine.Node{
		class("computer", activedirectory.SubClassOf, "user", activedirectory.AuxiliaryClass, "ipHost",
			activedirectory.SystemPossSuperiors, values("container", "organizationalUnit", "domainDNS")),
		class("user", activedirectory.SubClassOf, "organizationalPerson", activedirectory.SystemPossSuperiors, values("builtinDomain", "domainDNS")),
		class("organizationalPerson", activedirectory.SubClassOf, "top", activedirectory.PossSuperiors, values("organization")),
		class("ipHost", activedirectory.SubClassOf, "top", activedirectory.PossSuperiors, values("exampleRack")),
		class("top"),
	}
	for _, c := range []struct {
		name    string
		typ     engine.NodeType
		classes []string
		want    bool
	}{
		{"organizational unit", engine.NodeTypeOrganizationalUnit, []string{"top", "organizationalUnit"}, true},
		{"builtin domain, from user", engine.NodeTypeBuiltinDomain, []string{"top", "builtinDomain"}, true},
		{"organization, from organizationalPerson", engine.NodeTypeOther, []string{"top", "organization"}, true},
		{"subclass of container", engine.NodeTypeContainer, []string{"top", "container", "exampleContainer"}, true},
		{"from auxiliary class", engine.NodeTypeOther, []string{"top", "exampleRack"}, true},
		{"computer", engine.NodeTypeComputer, []string{"top", "person", "organizationalPerson", "user", "computer"}, false},
		{"group", engine.NodeTypeGroup, []string{"top", "group"}, false},
		{"typed container, not allowed by schema", engine.NodeTypeContainer, []string{"top", "exampleStore"}, false},
	} {
		target := engine.NewNode(engine.Name, "Target", engine.Type, c.typ.ValueString(), engine.ObjectClass, values(c.classes...),
			engine.DistinguishedName, "CN=Target,DC=example,DC=com")
		graph := newADTestGraph(append(schema, target)...)
		if got := CanContain(graph, "computer", engine.NodeTypeContainer)(target); got != c.want {
			t.Errorf("%v: %v, want %v", c.name, got, c.want)
		}
		// Without the schema, only the fallback types.
		graph = newADTestGraph(target)
		if got := CanContain(graph, "computer", engine.NodeTypeContainer)(target); got != (c.typ == engine.NodeTypeContainer) {
			t.Errorf("%v without schema: %v", c.name, got)
		}
	}
}
