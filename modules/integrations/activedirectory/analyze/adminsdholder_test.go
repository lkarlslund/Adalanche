package analyze

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestAdminSDHolderProtectedSet(t *testing.T) {
	const child = "DC=child,DC=example,DC=test"
	principal := func(name, sid string, kind engine.AttributeValue) *engine.Node {
		return engine.NewNode(engine.Name, name, engine.Type, kind, engine.ObjectSid, engine.NV(mustSID(t, sid)), engine.DomainContext, child)
	}
	user, group, computer := engine.NodeTypeUser.ValueString(), engine.NodeTypeGroup.ValueString(), engine.NodeTypeComputer.ValueString()
	domain := engine.NewNode(engine.DistinguishedName, child, engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-21-1-2-3")))
	holder := engine.NewNode(engine.DistinguishedName, "CN=AdminSDHolder,CN=System,"+child, engine.DomainContext, child)
	// dSHeuristics lives under the forest root, not the child domain. The
	// 16th character excludes Account Operators.
	heuristics := engine.NewNode(engine.Name, "Directory Service",
		engine.DistinguishedName, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=example,DC=test",
		activedirectory.DsHeuristics, "0000000001000001")

	da := principal("Domain Admins", "S-1-5-21-1-2-3-512", group)
	admin := principal("admin", "S-1-5-21-1-2-3-1001", user)
	nested := principal("nested", "S-1-5-21-1-2-3-1002", group)
	nestedUser := principal("nested user", "S-1-5-21-1-2-3-1003", user)
	foreign := principal("foreign", "S-1-5-21-9-9-9-1001", user)
	accountOps := principal("Account Operators", "S-1-5-32-548", group)
	operator := principal("operator", "S-1-5-21-1-2-3-1004", user)
	backupOps := principal("Backup Operators", "S-1-5-32-551", group)
	backup := principal("backup", "S-1-5-21-1-2-3-1005", user)
	dcs := principal("Domain Controllers", "S-1-5-21-1-2-3-516", group)
	dc := principal("dc", "S-1-5-21-1-2-3-1006", computer)
	krbtgt := principal("krbtgt", "S-1-5-21-1-2-3-502", user)
	other := principal("other", "S-1-5-21-1-2-3-1007", user)

	graph := newADTestGraph(domain, holder, heuristics, da, admin, nested, nestedUser, foreign, accountOps, operator, backupOps, backup, dcs, dc, krbtgt, other)
	for _, m := range [][2]*engine.Node{{admin, da}, {nested, da}, {nestedUser, nested}, {foreign, da}, {operator, accountOps}, {backup, backupOps}, {dc, dcs}} {
		graph.EdgeTo(m[0], m[1], activedirectory.EdgeMemberOfGroup)
	}
	addAdminSDHolderEdges(graph)

	for _, tt := range []struct {
		node *engine.Node
		want bool
	}{
		{da, true}, {admin, true}, {nested, true}, {nestedUser, true},
		{foreign, false},                       // not a principal of this domain
		{accountOps, false}, {operator, false}, // excluded by dwAdminSDExMask
		{backupOps, true}, {backup, true},
		{dcs, true}, {dc, false}, // the group only, not its members
		{krbtgt, true}, {other, false},
	} {
		if tt.want {
			requireEdgeSet(t, graph, holder, tt.node, activedirectory.EdgeOverwritesACL)
		} else {
			requireNoEdgeSet(t, graph, holder, tt.node, activedirectory.EdgeOverwritesACL)
		}
	}
}

func TestOwnerRightsAndHeuristics(t *testing.T) {
	owner := mustSID(t, "S-1-5-21-1-2-3-1001")
	sd := securityDescriptorWithACEs(allowACE(windowssecurity.OwnerSID, engine.RIGHT_READ_CONTROL, uuid.Nil))
	if !hasOwnerRightsACE(sd) {
		t.Error("an allow ACE for OWNER RIGHTS replaces the implicit rights")
	}
	inherit := allowACE(windowssecurity.OwnerSID, engine.RIGHT_READ_CONTROL, uuid.Nil)
	inherit.ACEFlags = engine.ACEFLAG_INHERIT_ONLY_ACE
	if hasOwnerRightsACE(securityDescriptorWithACEs(inherit)) {
		t.Error("an inherit-only ACE does not apply to the object itself")
	}

	sd.Owner = owner
	ownerNode := engine.NewNode(engine.ObjectSid, engine.NV(owner))
	graph := newADTestGraph(ownerNode)
	if got := aceTrustee(graph, sd, windowssecurity.OwnerSID, nil); got != ownerNode {
		t.Error("OWNER RIGHTS grants belong to the owner")
	}

	for heuristics, want := range map[string]bool{
		"":                              false,
		"0000000001000000000000000000":  false,
		"00000000010000000002000000000": false,
		"00000000010000000002000000001": true,
		"00000000010000000002000000003": false,
		"0000000001000000000200000000x": true,
	} {
		if got := blocksOwnerImplicitRights(heuristics); got != want {
			t.Errorf("%q: got %v, want %v", heuristics, got, want)
		}
	}
}

// Steps that follow group memberships must run after memberOf and member
// are resolved after the merge, so this runs the registered processors in
// their real order on memberships given only as attributes.
func TestMembershipConsumersRunAfterResolution(t *testing.T) {
	const domainDN = "DC=example,DC=test"
	daDN, protectedDN := "CN=Domain Admins,CN=Users,"+domainDN, "CN=Protected Users,CN=Users,"+domainDN
	domain := engine.NewNode(engine.DistinguishedName, domainDN, engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-21-1-2-3")))
	holder := engine.NewNode(engine.DistinguishedName, "CN=AdminSDHolder,CN=System,"+domainDN, engine.DomainContext, domainDN)
	group := func(dn, sid string) *engine.Node {
		return engine.NewNode(engine.Type, engine.NodeTypeGroup.ValueString(), engine.DistinguishedName, dn, engine.ObjectSid, engine.NV(mustSID(t, sid)), engine.DomainContext, domainDN)
	}
	da := group(daDN, "S-1-5-21-1-2-3-512")
	protectedUsers := group(protectedDN, "S-1-5-21-1-2-3-525")
	admin := engine.NewNode(engine.Type, engine.NodeTypeUser.ValueString(), engine.DistinguishedName, "CN=admin,CN=Users,"+domainDN,
		engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-21-1-2-3-1001")), engine.DomainContext, domainDN,
		activedirectory.MemberOf, daDN)
	admin.Add(activedirectory.MemberOf, engine.NV(protectedDN))

	graph := newADTestGraph(domain, holder, da, protectedUsers, admin)
	for priority := engine.AfterMergeLow; priority <= engine.AfterMerge; priority++ {
		if err := engine.Process(graph, "test", -1, priority); err != nil {
			t.Fatal(err)
		}
	}
	requireEdgeSet(t, graph, holder, admin, activedirectory.EdgeOverwritesACL)
	if !admin.HasTag("protected_user") {
		t.Error("member of Protected Users was not tagged")
	}
}
