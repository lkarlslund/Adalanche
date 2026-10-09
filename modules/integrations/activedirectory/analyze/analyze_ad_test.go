package analyze

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
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
	tg := engine.NewIndexedGraph()
	tg.AddDefaultFlex(engine.DataLoader, engine.NV((&ADLoader{}).Name()))
	for _, node := range nodes {
		enginetest.Add(tg, node)
	}
	return tg
}

// runTx runs a processor in a transaction and commits it.
func runTx(graph *engine.IndexedGraph, processor func(*engine.Tx)) {
	tx := graph.Begin("test")
	processor(tx)
	if err := tx.Commit(); err != nil {
		panic(err)
	}
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
	runTx(graph, resolveMemberOfAndMember)

	requireEdgeSet(t, graph, user, group, activedirectory.EdgeMemberOfGroup)
}

func TestMachinesAffectedByGPOAddsAffectedByGPOEdge(t *testing.T) {
	domainSID := mustSID(t, "S-1-5-21-111-222-333")
	computerSID := mustSID(t, "S-1-5-21-111-222-333-1001")
	authenticatedUsersSID := windowssecurity.AuthenticatedUsersSID

	gpo := engine.NewNode(
		engine.Name, "Workstation Policy",
		engine.DistinguishedName, "CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System,DC=example,DC=com",
	)
	authenticatedUsers := engine.NewNode(
		engine.Name, "Authenticated Users",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.ObjectSid, authenticatedUsersSID,
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

	graph := newADTestGraph(gpo, ou, computer, machine, authenticatedUsers)
	enginetest.Set(graph, gpo, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(authenticatedUsersSID, engine.RIGHT_DS_READ_PROPERTY, uuid.Nil),
		allowACE(authenticatedUsersSID, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightApplyGroupPolicy),
	)))
	enginetest.ChildOf(graph, computer, ou)
	enginetest.EdgeTo(graph, computer, authenticatedUsers, activedirectory.EdgeMemberOfGroup)
	if computer.Type() != engine.NodeTypeComputer {
		t.Fatalf("expected computer type %q, got %q", engine.NodeTypeComputer.String(), computer.Type().String())
	}
	if machine.Type() != ObjectTypeMachine {
		t.Fatalf("expected machine type %q, got %q", ObjectTypeMachine.String(), machine.Type().String())
	}

	runTx(graph, addMachinesAffectedByGPO)

	requireEdgeSet(t, graph, gpo, machine, activedirectory.EdgeAffectedByGPO)
}

func TestMachinesAffectedByGPORequiresApplyGroupPolicy(t *testing.T) {
	domainSID := mustSID(t, "S-1-5-21-111-222-333")
	computerSID := mustSID(t, "S-1-5-21-111-222-333-1001")
	authenticatedUsersSID := windowssecurity.AuthenticatedUsersSID

	gpo := engine.NewNode(
		engine.Name, "Read Only Policy",
		engine.DistinguishedName, "CN={22222222-2222-2222-2222-222222222222},CN=Policies,CN=System,DC=example,DC=com",
	)
	authenticatedUsers := engine.NewNode(
		engine.Name, "Authenticated Users",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.ObjectSid, authenticatedUsersSID,
	)
	ou := engine.NewNode(
		engine.Name, "Workstations",
		engine.DistinguishedName, "OU=Workstations,DC=example,DC=com",
		activedirectory.GPLink, "[LDAP://CN={22222222-2222-2222-2222-222222222222},CN=Policies,CN=System,DC=example,DC=com;0]",
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

	graph := newADTestGraph(gpo, ou, computer, machine, authenticatedUsers)
	enginetest.Set(graph, gpo, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(authenticatedUsersSID, engine.RIGHT_DS_READ_PROPERTY, uuid.Nil),
	)))
	enginetest.ChildOf(graph, computer, ou)
	enginetest.EdgeTo(graph, computer, authenticatedUsers, activedirectory.EdgeMemberOfGroup)
	runTx(graph, addMachinesAffectedByGPO)

	requireNoEdgeSet(t, graph, gpo, machine, activedirectory.EdgeAffectedByGPO)
}

func TestMachinesAffectedByGPORequiresReadAccess(t *testing.T) {
	domainSID := mustSID(t, "S-1-5-21-111-222-333")
	computerSID := mustSID(t, "S-1-5-21-111-222-333-1001")
	authenticatedUsersSID := windowssecurity.AuthenticatedUsersSID

	gpo := engine.NewNode(
		engine.Name, "Apply Only Policy",
		engine.DistinguishedName, "CN={33333333-3333-3333-3333-333333333333},CN=Policies,CN=System,DC=example,DC=com",
	)
	authenticatedUsers := engine.NewNode(
		engine.Name, "Authenticated Users",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.ObjectSid, authenticatedUsersSID,
	)
	ou := engine.NewNode(
		engine.Name, "Workstations",
		engine.DistinguishedName, "OU=Workstations,DC=example,DC=com",
		activedirectory.GPLink, "[LDAP://CN={33333333-3333-3333-3333-333333333333},CN=Policies,CN=System,DC=example,DC=com;0]",
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

	graph := newADTestGraph(gpo, ou, computer, machine, authenticatedUsers)
	enginetest.Set(graph, gpo, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(authenticatedUsersSID, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightApplyGroupPolicy),
	)))
	enginetest.ChildOf(graph, computer, ou)
	enginetest.EdgeTo(graph, computer, authenticatedUsers, activedirectory.EdgeMemberOfGroup)
	runTx(graph, addMachinesAffectedByGPO)

	requireNoEdgeSet(t, graph, gpo, machine, activedirectory.EdgeAffectedByGPO)
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

	graph := newADTestGraph(domain)
	enginetest.Set(graph, domain, engine.NTSecurityDescriptor, engine.NV(&sd))
	runTx(graph, addDomainDNSDCSyncEdges)

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

	graph := newADTestGraph(target)
	enginetest.Set(graph, target, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_WRITE_DACL, uuid.Nil),
	)))
	runTx(graph, addACLRuleEdges)

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

	ou := engine.NewNode(
		engine.Name, "Users",
		engine.Type, engine.NodeTypeOrganizationalUnit.ValueString(),
		engine.DistinguishedName, "OU=Users,DC=example,DC=com",
	)

	graph := newADTestGraph(account, ou)
	enginetest.Set(graph, account, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_CONTROL_ACCESS, ResetPwd),
	)))
	enginetest.Set(graph, ou, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_CONTROL_ACCESS, ResetPwd),
	)))
	runTx(graph, addACLRuleEdges)

	principal, found := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	if !found {
		t.Fatal("expected SID principal to be created")
	}
	requireEdgeSet(t, graph, principal, account, activedirectory.EdgeResetPassword)
	requireNoEdgeSet(t, graph, principal, ou, activedirectory.EdgeResetPassword)
}

func TestApplyDownLevelLogonNamePatches(t *testing.T) {
	crossRef := engine.NewNode(
		engine.ObjectClass, "crossRef",
		NCName, "DC=example,DC=com",
		NetBIOSName, "EXAMPLE",
	)
	user := engine.NewNode(
		engine.Name, "Alice",
		engine.SAMAccountName, "alice",
		engine.DistinguishedName, "CN=Alice,OU=Users,DC=example,DC=com",
	)

	graph := newADTestGraph(crossRef, user)
	runTx(graph, applyDownLevelLogonNamePatches)

	if got := user.OneAttrString(engine.DownLevelLogonName); got != `EXAMPLE\alice` {
		t.Fatalf("expected down-level logon name, got %q", got)
	}
}

func TestApplyDomainContextPatches(t *testing.T) {
	user := engine.NewNode(
		engine.Name, "Alice",
		engine.DistinguishedName, "CN=Alice,OU=Users,DC=example,DC=com",
	)

	graph := newADTestGraph(user)
	runTx(graph, applyDomainContextPatches)

	if got := user.OneAttrString(engine.DomainContext); got != "DC=example,DC=com" {
		t.Fatalf("expected domain context, got %q", got)
	}
}

func TestApplyObjectClassAndCategoryPatches(t *testing.T) {
	schemaClass := engine.NewNode(
		engine.LDAPDisplayName, "user",
		activedirectory.SchemaIDGUID, ObjectGuidUser,
	)
	objectCategory := engine.NewNode(
		engine.DistinguishedName, "CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com",
		activedirectory.SchemaIDGUID, ObjectGuidUser,
		activedirectory.Name, "User",
	)
	user := engine.NewNode(
		engine.Name, "Alice",
		engine.ObjectClass, "user",
		engine.ObjectCategory, "CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com",
	)

	graph := newADTestGraph(schemaClass, objectCategory, user)
	runTx(graph, applyObjectClassAndCategoryPatches)

	if got := user.Attr(engine.ObjectClassGUIDs).Len(); got != 1 {
		t.Fatalf("expected one object class guid, got %d", got)
	}
	if got := user.OneAttrString(engine.Type); got != "User" {
		t.Fatalf("expected type to be set from object category, got %q", got)
	}
}

func TestApplyProtectedUserTags(t *testing.T) {
	protectedUsers := engine.NewNode(
		engine.Name, "Protected Users",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.ObjectSid, mustSID(t, "S-1-5-21-111-222-333-525"),
	)
	user := engine.NewNode(
		engine.Name, "Alice",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=Alice,OU=Users,DC=example,DC=com",
	)

	graph := newADTestGraph(protectedUsers, user)
	enginetest.EdgeTo(graph, user, protectedUsers, activedirectory.EdgeMemberOfGroup)

	runTx(graph, applyProtectedUserTags)

	if !user.HasTag("protected_user") {
		t.Fatal("expected protected_user tag")
	}
}

func TestApplyWellKnownSIDDisplayNames(t *testing.T) {
	group := engine.NewNode(
		engine.Name, "Builtin Admins",
		engine.ObjectSid, windowssecurity.AuthenticatedUsersSID,
	)

	graph := newADTestGraph(group)
	runTx(graph, applyWellKnownSIDDisplayNames)

	if got := group.OneAttrString(engine.DisplayName); got == "" {
		t.Fatal("expected display name to be filled from known SID")
	}
}

func TestApplyIndirectMemberOfPatches(t *testing.T) {
	top := engine.NewNode(
		engine.Name, "TopGroup",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.DistinguishedName, "CN=TopGroup,OU=Groups,DC=example,DC=com",
	)
	mid := engine.NewNode(
		engine.Name, "MidGroup",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.DistinguishedName, "CN=MidGroup,OU=Groups,DC=example,DC=com",
	)
	leaf := engine.NewNode(
		engine.Name, "LeafUser",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=LeafUser,OU=Users,DC=example,DC=com",
	)

	graph := newADTestGraph(top, mid, leaf)
	enginetest.EdgeTo(graph, mid, top, activedirectory.EdgeMemberOfGroup)
	enginetest.EdgeTo(graph, leaf, mid, activedirectory.EdgeMemberOfGroup)

	runTx(graph, applyIndirectMemberOfPatches)

	indirect := top.Attr(MemberOfIndirect)
	if indirect.Len() != 1 || indirect.First().String() != leaf.OneAttrString(engine.DistinguishedName) {
		t.Fatalf("expected indirect member DN %q, got %v", leaf.OneAttrString(engine.DistinguishedName), indirect)
	}
}

func TestWriteAllowedToActAndRBCDAddEdges(t *testing.T) {
	operatorSID := mustSID(t, "S-1-5-21-111-222-333-1202")
	target := engine.NewNode(
		engine.Name, "APP01$",
		engine.Type, engine.NodeTypeComputer.ValueString(),
		activedirectory.Type, engine.NodeTypeComputer.ValueString(),
		engine.DistinguishedName, "CN=APP01,OU=Servers,DC=example,DC=com",
	)

	graph := newADTestGraph(target)
	enginetest.Set(graph, target, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_WRITE_PROPERTY, AttributeAllowedToActOnBehalfOfOtherIdentity),
	)))
	enginetest.Set(graph, target, activedirectory.MSDSAllowedToActOnBehalfOfOtherIdentity, engine.NV(securityDescriptorWithACEs(
		engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, Mask: engine.RIGHT_GENERIC_ALL, SID: operatorSID},
	)))
	runTx(graph, addACLRuleEdges)
	runTx(graph, addRBCDEdges)

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

	group := engine.NewNode(
		engine.Name, "Operators",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.DistinguishedName, "CN=Operators,OU=Groups,DC=example,DC=com",
	)

	graph := newADTestGraph(user, group)
	enginetest.Set(graph, user, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_WRITE_PROPERTY, AttributeMSDSKeyCredentialLink),
	)))
	enginetest.Set(graph, group, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_WRITE_PROPERTY, AttributeMSDSKeyCredentialLink),
	)))
	runTx(graph, addACLRuleEdges)

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

	wrongMask := engine.NewNode(
		engine.Name, "Wrong Mask User",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=WrongMask,OU=Users,DC=example,DC=com",
	)

	graph := newADTestGraph(allowed, wrongMask)
	enginetest.Set(graph, allowed, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_CONTROL_ACCESS, uuid.Nil),
	)))
	enginetest.Set(graph, wrongMask, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(operatorSID, engine.RIGHT_DS_WRITE_PROPERTY, uuid.Nil),
	)))
	runTx(graph, addACLRuleEdges)

	principal, found := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	if !found {
		t.Fatal("expected SID principal to be created")
	}
	requireEdgeSet(t, graph, principal, allowed, activedirectory.EdgeAllExtendedRights)
	requireNoEdgeSet(t, graph, principal, wrongMask, activedirectory.EdgeAllExtendedRights)
}
