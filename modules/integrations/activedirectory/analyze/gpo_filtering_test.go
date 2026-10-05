package analyze

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func denyACE(sid windowssecurity.SID, mask engine.Mask, objectType uuid.UUID) engine.ACE {
	ace := allowACE(sid, mask, objectType)
	ace.Type = engine.ACETYPE_ACCESS_DENIED
	if objectType != uuid.Nil {
		ace.Type = engine.ACETYPE_ACCESS_DENIED_OBJECT
	}
	return ace
}

// gpoFilteringAffects links one GPO above a computer that is a member of
// the groups in chain (chain[0] directly, each later group through the one
// before it) and reports whether the machine is affected by the GPO.
func gpoFilteringAffects(t *testing.T, chain []windowssecurity.SID, aces ...engine.ACE) bool {
	t.Helper()
	computerSID := mustSID(t, "S-1-5-21-111-222-333-1001")
	gpoDN := "CN={44444444-4444-4444-4444-444444444444},CN=Policies,CN=System,DC=example,DC=com"
	gpo := engine.NewNode(engine.Name, "Filtered Policy", engine.DistinguishedName, gpoDN)
	ou := engine.NewNode(
		engine.Name, "Workstations",
		engine.DistinguishedName, "OU=Workstations,DC=example,DC=com",
		activedirectory.GPLink, "[LDAP://"+gpoDN+";0]",
	)
	computer := engine.NewNode(
		engine.Name, "WS01$",
		engine.Type, engine.NodeTypeComputer.ValueString(),
		engine.DistinguishedName, "CN=WS01,OU=Workstations,DC=example,DC=com",
		engine.ObjectSid, computerSID,
	)
	machine := engine.NewNode(
		engine.Name, "WS01",
		engine.Type, ObjectTypeMachine.ValueString(),
		DomainJoinedSID, computerSID,
		attrs.DomainJoinedSID, computerSID,
	)

	nodes := []*engine.Node{gpo, ou, computer, machine}
	var groups []*engine.Node
	for _, sid := range chain {
		group := engine.NewNode(engine.Type, engine.NodeTypeGroup.ValueString(), engine.ObjectSid, sid)
		groups = append(groups, group)
		nodes = append(nodes, group)
	}
	graph := newADTestGraph(nodes...)
	enginetest.Set(graph, gpo, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(aces...)))
	enginetest.ChildOf(graph, computer, ou)
	member := computer
	for _, group := range groups {
		enginetest.EdgeTo(graph, member, group, activedirectory.EdgeMemberOfGroup)
		member = group
	}

	runTx(graph, addMachinesAffectedByGPO)
	edges, found := graph.GetEdge(gpo, machine)
	return found && edges.IsSet(activedirectory.EdgeAffectedByGPO)
}

func TestGPOSecurityFilteringFollowsTheToken(t *testing.T) {
	inner := mustSID(t, "S-1-5-21-111-222-333-2001")
	outer := mustSID(t, "S-1-5-21-111-222-333-2002")
	other := mustSID(t, "S-1-5-21-111-222-333-2003")
	authenticated := windowssecurity.AuthenticatedUsersSID
	read := allowACE(authenticated, engine.RIGHT_DS_READ_PROPERTY, uuid.Nil)
	apply := func(sid windowssecurity.SID) engine.ACE {
		return allowACE(sid, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightApplyGroupPolicy)
	}
	denyApply := func(sid windowssecurity.SID) engine.ACE {
		return denyACE(sid, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightApplyGroupPolicy)
	}

	for _, tt := range []struct {
		name  string
		chain []windowssecurity.SID
		aces  []engine.ACE
		want  bool
	}{
		{"authenticated users without explicit membership", nil, []engine.ACE{read, apply(authenticated)}, true},
		{"applied to a nested group", []windowssecurity.SID{inner, outer}, []engine.ACE{read, apply(outer)}, true},
		{"applied to a group the computer is not in", []windowssecurity.SID{inner}, []engine.ACE{read, apply(other)}, false},
		{"deny for a group the computer is in", []windowssecurity.SID{inner}, []engine.ACE{denyApply(inner), read, apply(authenticated)}, false},
		{"deny through nesting", []windowssecurity.SID{inner, outer}, []engine.ACE{denyApply(outer), read, apply(authenticated)}, false},
		{"deny for another group", []windowssecurity.SID{inner}, []engine.ACE{denyApply(other), read, apply(authenticated)}, true},
		{"deny of everything for the computer's group", []windowssecurity.SID{inner}, []engine.ACE{denyACE(inner, engine.RIGHT_GENERIC_ALL, uuid.Nil), read, apply(authenticated)}, false},
		{"deny of an unrelated right", []windowssecurity.SID{inner}, []engine.ACE{denyACE(inner, engine.RIGHT_WRITE_DACL, uuid.Nil), read, apply(authenticated)}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := gpoFilteringAffects(t, tt.chain, tt.aces...); got != tt.want {
				t.Fatalf("affected = %v, want %v", got, tt.want)
			}
		})
	}
}

// GPO targeting must see memberships that are only resolved from memberOf
// during post-merge processing, so this runs the registered processors in
// their real order rather than calling addMachinesAffectedByGPO directly.
func TestGPOTargetingRunsAfterMembershipResolution(t *testing.T) {
	computerSID := mustSID(t, "S-1-5-21-111-222-333-1001")
	groupSID := mustSID(t, "S-1-5-21-111-222-333-2001")
	gpoDN := "CN={55555555-5555-5555-5555-555555555555},CN=Policies,CN=System,DC=example,DC=com"
	groupDN := "CN=Kiosks,OU=Groups,DC=example,DC=com"

	gpo := engine.NewNode(engine.Name, "Kiosk Policy", engine.DistinguishedName, gpoDN)
	ou := engine.NewNode(
		engine.Name, "Workstations",
		engine.DistinguishedName, "OU=Workstations,DC=example,DC=com",
		activedirectory.GPLink, "[LDAP://"+gpoDN+";0]",
	)
	group := engine.NewNode(
		engine.Name, "Kiosks",
		engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.DistinguishedName, groupDN,
		engine.ObjectSid, groupSID,
	)
	computer := engine.NewNode(
		engine.Name, "WS01$",
		engine.Type, engine.NodeTypeComputer.ValueString(),
		engine.DistinguishedName, "CN=WS01,OU=Workstations,DC=example,DC=com",
		engine.ObjectSid, computerSID,
		activedirectory.MemberOf, groupDN,
	)
	machine := engine.NewNode(
		engine.Name, "WS01",
		engine.Type, ObjectTypeMachine.ValueString(),
		DomainJoinedSID, computerSID,
		attrs.DomainJoinedSID, computerSID,
	)
	graph := newADTestGraph(gpo, ou, group, computer, machine)
	enginetest.Set(graph, gpo, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(windowssecurity.AuthenticatedUsersSID, engine.RIGHT_DS_READ_PROPERTY, uuid.Nil),
		allowACE(groupSID, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightApplyGroupPolicy),
	)))
	enginetest.ChildOf(graph, computer, ou)

	if err := engine.RunPhase(graph, engine.AnyLoader, engine.AnalysisPhase); err != nil {
		t.Fatal(err)
	}
	requireEdgeSet(t, graph, gpo, machine, activedirectory.EdgeAffectedByGPO)
}
