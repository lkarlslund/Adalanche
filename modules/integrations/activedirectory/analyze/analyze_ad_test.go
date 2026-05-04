package analyze

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	attrs "github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func mustSID(t *testing.T, value string) windowssecurity.SID {
	t.Helper()

	sid, err := windowssecurity.ParseStringSID(value)
	if err != nil {
		t.Fatalf("parse SID %q: %v", value, err)
	}
	return sid
}

func newADTestGraph(nodes ...*engine.Node) *engine.IndexedGraph {
	tg := engine.NewLoaderObjects(&ADLoader{})
	for _, node := range nodes {
		tg.Add(node)
	}
	return tg
}

func requireEdgeSet(t *testing.T, graph *engine.IndexedGraph, source, target *engine.Node, edge engine.Edge) {
	t.Helper()

	edges, found := graph.GetEdge(source, target)
	if !found {
		t.Fatalf("expected edge from %q to %q", source.Label(), target.Label())
	}
	if !edges.IsSet(edge) {
		t.Fatalf("expected edge %q from %q to %q, got %v", edge.String(), source.Label(), target.Label(), edges.Edges())
	}
}

func requireNoEdgeSet(t *testing.T, graph *engine.IndexedGraph, source, target *engine.Node, edge engine.Edge) {
	t.Helper()

	edges, found := graph.GetEdge(source, target)
	if !found {
		return
	}
	if edges.IsSet(edge) {
		t.Fatalf("did not expect edge %q from %q to %q", edge.String(), source.Label(), target.Label())
	}
}

func allowACE(sid windowssecurity.SID, mask engine.Mask, objectType uuid.UUID) engine.ACE {
	ace := engine.ACE{
		Type: engine.ACETYPE_ACCESS_ALLOWED,
		Mask: mask,
		SID:  sid,
	}
	if objectType != uuid.Nil {
		ace.Type = engine.ACETYPE_ACCESS_ALLOWED_OBJECT
		ace.Flags = engine.OBJECT_TYPE_PRESENT
		ace.ObjectType = objectType
	}
	return ace
}

func securityDescriptorWithACEs(aces ...engine.ACE) *engine.SecurityDescriptor {
	return &engine.SecurityDescriptor{
		Control: engine.CONTROLFLAG_DACL_PRESENT,
		DACL: engine.ACL{
			Revision: 2,
			Entries:  aces,
		},
	}
}

func TestMemberOfResolutionAddsMemberOfGroupEdge(t *testing.T) {
	user := engine.NewNode(
		engine.Name, "Alice",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=Alice,OU=Users,DC=example,DC=com",
		activedirectory.MemberOf, "CN=Operators,OU=Groups,DC=example,DC=com",
	)
	group := engine.NewNode(
		engine.Name, "Operators",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.DistinguishedName, "CN=Operators,OU=Groups,DC=example,DC=com",
	)

	graph := newADTestGraph(user, group)
	resolveMemberOfAndMember(graph)

	requireEdgeSet(t, graph, user, group, activedirectory.EdgeMemberOfGroup)
}

func TestMachinesAffectedByGPOAddsAffectedByGPOEdge(t *testing.T) {
	domainSID := mustSID(t, "S-1-5-21-111-222-333")
	computerSID := mustSID(t, "S-1-5-21-111-222-333-1001")

	gpo := engine.NewNode(
		engine.Name, "Workstation Policy",
		engine.DistinguishedName, "CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System,DC=example,DC=com",
	)
	ou := engine.NewNode(
		engine.Name, "Workstations",
		engine.DistinguishedName, "OU=Workstations,DC=example,DC=com",
		activedirectory.GPLink, "[LDAP://CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System,DC=example,DC=com;0]",
	)
	computer := engine.NewNode(
		engine.Name, "WS01$",
		engine.Type, engine.NodeTypeComputer.ValueString(),
		activedirectory.Type, engine.NodeTypeComputer.ValueString(),
		engine.DistinguishedName, "CN=WS01,OU=Workstations,DC=example,DC=com",
		engine.ObjectSid, computerSID,
		engine.DomainContext, "example.com",
		engine.DataSource, "example",
	)
	machine := engine.NewNode(
		engine.Name, "WS01",
		engine.Type, ObjectTypeMachine.ValueString(),
		activedirectory.Type, ObjectTypeMachine.ValueString(),
		DomainJoinedSID, computerSID,
		attrs.DomainJoinedSID, computerSID,
		engine.ObjectSid, domainSID,
		engine.DomainContext, "example.com",
		engine.DataSource, "example",
	)

	computer.ChildOf(ou)

	graph := newADTestGraph(gpo, ou, computer, machine)
	if computer.Type() != engine.NodeTypeComputer {
		t.Fatalf("expected computer type %q, got %q", engine.NodeTypeComputer.String(), computer.Type().String())
	}
	if machine.Type() != ObjectTypeMachine {
		t.Fatalf("expected machine type %q, got %q", ObjectTypeMachine.String(), machine.Type().String())
	}

	addMachinesAffectedByGPO(graph)

	requireEdgeSet(t, graph, gpo, machine, activedirectory.EdgeAffectedByGPO)
}

func TestDomainDNSDCSyncProcessorAddsReplicationAndCallEdges(t *testing.T) {
	replicationSID := mustSID(t, "S-1-5-21-111-222-333-1105")
	domain := engine.NewNode(
		engine.Name, "example.com",
		engine.Type, engine.NodeTypeDomainDNS.ValueString(),
		engine.ObjectClass, "domainDNS",
		engine.IsCriticalSystemObject, true,
		engine.DistinguishedName, "DC=example,DC=com",
		engine.DomainContext, "example.com",
		activedirectory.SystemFlags, int64(1),
	)

	sd := engine.SecurityDescriptor{
		Control: engine.CONTROLFLAG_DACL_PRESENT,
		DACL: engine.ACL{
			Revision: 2,
			Entries: []engine.ACE{
				{
					Type: engine.ACETYPE_ACCESS_ALLOWED,
					Mask: engine.RIGHT_DS_CONTROL_ACCESS,
					SID:  replicationSID,
				},
			},
		},
	}
	domain.Set(engine.NTSecurityDescriptor, engine.NV(&sd))

	graph := newADTestGraph(domain)
	addDomainDNSDCSyncEdges(graph)

	principal, found := graph.Find(engine.ObjectSid, engine.NV(replicationSID))
	if !found {
		t.Fatal("expected synthetic SID principal to be created")
	}
	dcsync, found := graph.FindTwo(
		engine.Type, engine.NodeTypeCallableServicePoint.ValueString(),
		engine.Name, engine.NV("DCsync"),
	)
	if !found {
		t.Fatal("expected DCsync helper node to be created")
	}

	requireEdgeSet(t, graph, domain, dcsync, activedirectory.EdgeControls)
	requireEdgeSet(t, graph, principal, domain, activedirectory.EdgeDSReplicationGetChanges)
	requireEdgeSet(t, graph, principal, domain, activedirectory.EdgeDSReplicationGetChangesAll)
	requireEdgeSet(t, graph, principal, domain, activedirectory.EdgeDSReplicationGetChangesInFilteredSet)
	requireEdgeSet(t, graph, principal, dcsync, activedirectory.EdgeCall)
}

func TestWriteDACLAddsEdge(t *testing.T) {
	operatorSID := mustSID(t, "S-1-5-21-111-222-333-1200")
	target := engine.NewNode(
		engine.Name, "Target User",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=Target,OU=Users,DC=example,DC=com",
	)
	target.Set(engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_WRITE_DACL, uuid.Nil),
	)))

	graph := newADTestGraph(target)
	addWriteDACLEdges(graph)

	principal, found := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	if !found {
		t.Fatal("expected SID principal to be created")
	}
	requireEdgeSet(t, graph, principal, target, activedirectory.EdgeWriteDACL)
}

func TestResetPasswordOnlyTargetsAccounts(t *testing.T) {
	operatorSID := mustSID(t, "S-1-5-21-111-222-333-1201")
	account := engine.NewNode(
		engine.Name, "Resettable User",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=Resettable,OU=Users,DC=example,DC=com",
	)
	account.Set(engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_CONTROL_ACCESS, ResetPwd),
	)))

	ou := engine.NewNode(
		engine.Name, "Users",
		engine.Type, engine.NodeTypeOrganizationalUnit.ValueString(),
		engine.DistinguishedName, "OU=Users,DC=example,DC=com",
	)
	ou.Set(engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_CONTROL_ACCESS, ResetPwd),
	)))

	graph := newADTestGraph(account, ou)
	addResetPasswordEdges(graph)

	principal, found := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	if !found {
		t.Fatal("expected SID principal to be created")
	}
	requireEdgeSet(t, graph, principal, account, activedirectory.EdgeResetPassword)
	requireNoEdgeSet(t, graph, principal, ou, activedirectory.EdgeResetPassword)
}

func TestWriteAllowedToActAndRBCDAddEdges(t *testing.T) {
	operatorSID := mustSID(t, "S-1-5-21-111-222-333-1202")
	target := engine.NewNode(
		engine.Name, "APP01$",
		engine.Type, engine.NodeTypeComputer.ValueString(),
		activedirectory.Type, engine.NodeTypeComputer.ValueString(),
		engine.DistinguishedName, "CN=APP01,OU=Servers,DC=example,DC=com",
	)
	target.Set(engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_WRITE_PROPERTY, AttributeAllowedToActOnBehalfOfOtherIdentity),
	)))
	target.Set(activedirectory.MSDSAllowedToActOnBehalfOfOtherIdentity, engine.NV(securityDescriptorWithACEs(
		engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, Mask: engine.RIGHT_GENERIC_ALL, SID: operatorSID},
	)))

	graph := newADTestGraph(target)
	addWriteAllowedToActEdges(graph)
	addRBCDEdges(graph)

	principal, found := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	if !found {
		t.Fatal("expected SID principal to be created")
	}
	requireEdgeSet(t, graph, principal, target, activedirectory.EdgeWriteAllowedToAct)
	requireEdgeSet(t, graph, principal, target, EdgeRBCD)
}

func TestWriteKeyCredentialLinkOnlyTargetsUsersAndComputers(t *testing.T) {
	operatorSID := mustSID(t, "S-1-5-21-111-222-333-1203")
	user := engine.NewNode(
		engine.Name, "KeyCred User",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=KeyCred,OU=Users,DC=example,DC=com",
	)
	user.Set(engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_WRITE_PROPERTY, AttributeMSDSKeyCredentialLink),
	)))

	group := engine.NewNode(
		engine.Name, "Operators",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.DistinguishedName, "CN=Operators,OU=Groups,DC=example,DC=com",
	)
	group.Set(engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_WRITE_PROPERTY, AttributeMSDSKeyCredentialLink),
	)))

	graph := newADTestGraph(user, group)
	addWriteKeyCredentialLinkEdges(graph)

	principal, found := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	if !found {
		t.Fatal("expected SID principal to be created")
	}
	requireEdgeSet(t, graph, principal, user, activedirectory.EdgeWriteKeyCredentialLink)
	requireNoEdgeSet(t, graph, principal, group, activedirectory.EdgeWriteKeyCredentialLink)
}

func TestAllExtendedRightsAddsEdgeAndSkipsWrongMask(t *testing.T) {
	operatorSID := mustSID(t, "S-1-5-21-111-222-333-1204")
	allowed := engine.NewNode(
		engine.Name, "Allowed User",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=Allowed,OU=Users,DC=example,DC=com",
	)
	allowed.Set(engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_CONTROL_ACCESS, uuid.Nil),
	)))

	wrongMask := engine.NewNode(
		engine.Name, "Wrong Mask User",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=WrongMask,OU=Users,DC=example,DC=com",
	)
	wrongMask.Set(engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_WRITE_PROPERTY, uuid.Nil),
	)))

	graph := newADTestGraph(allowed, wrongMask)
	addAllExtendedRightsEdges(graph)

	principal, found := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	if !found {
		t.Fatal("expected SID principal to be created")
	}
	requireEdgeSet(t, graph, principal, allowed, activedirectory.EdgeAllExtendedRights)
	requireNoEdgeSet(t, graph, principal, wrongMask, activedirectory.EdgeAllExtendedRights)
}
