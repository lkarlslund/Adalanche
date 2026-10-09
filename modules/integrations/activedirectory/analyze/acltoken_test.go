package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestACLDeniesFollowTheTrusteeToken(t *testing.T) {
	const domain = "S-1-5-21-1-2-3"
	alice := domain + "-1001"
	helpdesk := domain + "-1100" // Alice is a member
	tier1 := domain + "-1200"    // Helpdesk is a member
	ops := domain + "-1300"      // unrelated
	domainUsers := domain + "-513"
	for _, tt := range []struct {
		name          string
		deny, trustee string
		want          bool
	}{
		{"deny on a group the trustee is nested in", tier1, alice, false},
		{"deny on a group a trustee group is nested in", tier1, helpdesk, false},
		{"deny on a group the trustee is not in", tier1, ops, true},
		{"deny on the primary group", domainUsers, alice, false},
		{"deny on Authenticated Users for an account", "S-1-5-11", alice, false},
		{"deny on Authenticated Users for a group", "S-1-5-11", helpdesk, true},
		{"deny on Everyone", "S-1-1-0", ops, false},
		{"deny on a member only", alice, helpdesk, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := engine.ParseSDDL("D:(D;;WD;;;" + tt.deny + ")(A;;WD;;;" + tt.trustee + ")")
			if err != nil {
				t.Fatal(err)
			}
			nodes := map[string]*engine.Node{
				alice: engine.NewNode(engine.Name, "Alice", engine.Type, engine.NodeTypeUser.ValueString(),
					engine.DistinguishedName, "CN=Alice,DC=example,DC=com", engine.ObjectSid, engine.NV(mustSID(t, alice)),
					activedirectory.MemberOf, "CN=Helpdesk,DC=example,DC=com"),
				helpdesk: engine.NewNode(engine.Name, "Helpdesk", engine.Type, engine.NodeTypeGroup.ValueString(),
					engine.DistinguishedName, "CN=Helpdesk,DC=example,DC=com", engine.ObjectSid, engine.NV(mustSID(t, helpdesk)),
					activedirectory.MemberOf, "CN=Tier1,DC=example,DC=com"),
				tier1: engine.NewNode(engine.Name, "Tier1", engine.Type, engine.NodeTypeGroup.ValueString(),
					engine.DistinguishedName, "CN=Tier1,DC=example,DC=com", engine.ObjectSid, engine.NV(mustSID(t, tier1))),
				ops: engine.NewNode(engine.Name, "Ops", engine.Type, engine.NodeTypeGroup.ValueString(),
					engine.DistinguishedName, "CN=Ops,DC=example,DC=com", engine.ObjectSid, engine.NV(mustSID(t, ops))),
				domainUsers: engine.NewNode(engine.Name, "Domain Users", engine.Type, engine.NodeTypeGroup.ValueString(),
					engine.DistinguishedName, "CN=Domain Users,DC=example,DC=com", engine.ObjectSid, engine.NV(mustSID(t, domainUsers))),
			}
			target := engine.NewNode(engine.Name, "Target", engine.DistinguishedName, "CN=Target,DC=example,DC=com",
				engine.NTSecurityDescriptor, engine.NV(&engine.SecurityDescriptor{Control: engine.CONTROLFLAG_DACL_PRESENT, DACL: acl}))
			all := []*engine.Node{target}
			for _, n := range nodes {
				all = append(all, n)
			}
			authenticatedUsers := engine.NewNode(engine.Name, "Authenticated Users", engine.ObjectSid, engine.NV(windowssecurity.AuthenticatedUsersSID))
			graph := newADTestGraph(append(all, authenticatedUsers)...)
			// What the membership processors add: memberOf, the primary
			// group, and Authenticated Users for accounts.
			runTx(graph, resolveMemberOfAndMember)
			enginetest.EdgeTo(graph, nodes[alice], nodes[domainUsers], activedirectory.EdgeMemberOfGroup)
			enginetest.EdgeTo(graph, nodes[alice], authenticatedUsers, activedirectory.EdgeMemberOfGroup)
			runTx(graph, addACLRuleEdges)
			if tt.want {
				requireEdgeSet(t, graph, nodes[tt.trustee], target, activedirectory.EdgeWriteDACL)
			} else {
				requireNoEdgeSet(t, graph, nodes[tt.trustee], target, activedirectory.EdgeWriteDACL)
			}
		})
	}
}

func TestTrusteeGrantedCountsOnlyTheTrusteesAllows(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	acl, err := engine.ParseSDDL("D:(A;;RP;;;S-1-1-0)(A;;CR;;;" + user + ")")
	if err != nil {
		t.Fatal(err)
	}
	sd := &engine.SecurityDescriptor{Control: engine.CONTROLFLAG_DACL_PRESENT, DACL: acl}
	graph := newADTestGraph()
	if TrusteeGranted(graph, sd, mustSID(t, user), nil, engine.RIGHT_DS_READ_PROPERTY, [16]byte{}) {
		t.Fatal("a right granted only to Everyone was attributed to the trustee")
	}
	if !TrusteeGranted(graph, sd, mustSID(t, user), nil, engine.RIGHT_DS_CONTROL_ACCESS, [16]byte{}) {
		t.Fatal("the trustee's own grant was not found")
	}
}

// A machine's local groups are in a token only for that machine's own
// accounts, even though the domain's Authenticated Users is a member there.
func TestTokensStayOffOtherMachinesLocalGroups(t *testing.T) {
	usersSID := windowssecurity.MustParseStringSID("S-1-5-32-545")
	graph := newADTestGraph()
	domainUsers := enginetest.AddNew(graph, engine.ObjectSid, engine.NV(windowssecurity.AuthenticatedUsersSID), engine.DomainContext, "DC=example,DC=com")
	account := enginetest.AddNew(graph, engine.Type, engine.NodeTypeUser.ValueString(), engine.ObjectSid, engine.NV(mustSID(t, "S-1-5-21-1-2-3-1100")), engine.DomainContext, "DC=example,DC=com")
	machine := enginetest.AddNew(graph, engine.Type, ObjectTypeMachine.ValueString(), engine.Name, "HOST01")
	local := func(sid windowssecurity.SID) *engine.Node {
		n := enginetest.AddNew(graph, engine.Type, engine.NodeTypeGroup.ValueString(), engine.ObjectSid, engine.NV(sid))
		enginetest.ChildOf(graph, n, machine)
		return n
	}
	localAuthUsers, localUsers := local(windowssecurity.AuthenticatedUsersSID), local(usersSID)
	localAccount := local(mustSID(t, "S-1-5-21-9-9-9-1001"))
	enginetest.EdgeTo(graph, account, domainUsers, activedirectory.EdgeMemberOfGroup)
	enginetest.Edge(graph, domainUsers, localAuthUsers, activedirectory.EdgeMemberOfGroup)
	enginetest.EdgeTo(graph, localAuthUsers, localUsers, activedirectory.EdgeMemberOfGroup)
	enginetest.EdgeTo(graph, localAccount, localUsers, activedirectory.EdgeMemberOfGroup)

	if _, found := memberSIDs(graph, account)[usersSID]; found {
		t.Error("a domain account's token has a machine's local Users group")
	}
	if _, found := memberSIDs(graph, localAccount)[usersSID]; !found {
		t.Error("a local account's token lacks its own machine's Users group")
	}
}
