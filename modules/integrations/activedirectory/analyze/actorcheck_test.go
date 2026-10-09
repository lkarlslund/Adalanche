package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/aql"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

// One group is granted Reset Password on a user, and a deny before it
// refuses the right to another group. An account in both groups is refused
// it; an account in only the granted group is not.
func TestReachRefusesDeniedAccounts(t *testing.T) {
	const (
		deniedSID  = "S-1-5-21-1-2-3-1101"
		grantedSID = "S-1-5-21-1-2-3-1102"
	)
	acl, err := engine.ParseSDDL("D:(D;;CR;;;" + deniedSID + ")(A;;CR;;;" + grantedSID + ")")
	if err != nil {
		t.Fatal(err)
	}
	sd := &engine.SecurityDescriptor{Control: engine.CONTROLFLAG_DACL_PRESENT, DACL: acl}

	for _, tt := range []struct {
		name          string
		bothMember    bool // the account in both groups is on the result
		grantedMember bool // the account in only the granted group is
		want          []string
		flow          int // routes through granted -> target
	}{
		{"refused account only", true, false, nil, 0},
		{"refused and allowed accounts", true, true, []string{"granted", "target", "allowed"}, 1},
		{"allowed account only", false, true, []string{"granted", "target", "allowed"}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			denied := engine.NewNode(engine.Name, "denied", engine.Type, engine.NodeTypeGroup.ValueString(), engine.ObjectSid, mustSID(t, deniedSID))
			granted := engine.NewNode(engine.Name, "granted", engine.Type, engine.NodeTypeGroup.ValueString(), engine.ObjectSid, mustSID(t, grantedSID))
			target := engine.NewNode(engine.Name, "target", engine.Type, engine.NodeTypeUser.ValueString(), engine.ObjectSid, mustSID(t, "S-1-5-21-1-2-3-1200"))
			both := engine.NewNode(engine.Name, "both", engine.Type, engine.NodeTypeUser.ValueString(), engine.ObjectSid, mustSID(t, "S-1-5-21-1-2-3-1201"))
			allowed := engine.NewNode(engine.Name, "allowed", engine.Type, engine.NodeTypeUser.ValueString(), engine.ObjectSid, mustSID(t, "S-1-5-21-1-2-3-1202"))
			g := newADTestGraph(denied, granted, target, both, allowed)
			enginetest.Set(g, target, engine.NTSecurityDescriptor, engine.NV(sd))
			enginetest.Tag(g, target, "account_enabled") // Reset Password counts only then
			enginetest.Update(g, func(tx *engine.Tx) {
				tx.EdgeBecause(granted, target, activedirectory.EdgeResetPassword, ACECause(1, acl.Entries[1]))
				if tt.bothMember {
					tx.EdgeTo(both, denied, activedirectory.EdgeMemberOfGroup)
					tx.EdgeTo(both, granted, activedirectory.EdgeMemberOfGroup)
				}
				if tt.grantedMember {
					tx.EdgeTo(allowed, granted, activedirectory.EdgeMemberOfGroup)
				}
			})

			resolver, err := aql.ParseAQLQuery("REACH start:(name=target)<-[]{1,4}-end:(|(name=both)(name=allowed))", g)
			if err != nil {
				t.Fatal(err)
			}
			result, err := resolver.Resolve(aql.NewResolverOptions())
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for node := range result.Nodes() {
				got = append(got, node.Label())
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got nodes %v, want %v", got, tt.want)
			}
			flow := 0
			result.IterateEdges(func(source, target *engine.Node, _ engine.EdgeBitmap, f int) bool {
				if source == granted && target.Label() == "target" {
					flow = f
				}
				return true
			})
			if flow != tt.flow {
				t.Errorf("flow through the granted group %d, want %d", flow, tt.flow)
			}
			for _, name := range tt.want {
				found := false
				for _, n := range got {
					found = found || n == name
				}
				if !found {
					t.Errorf("missing %s in %v", name, got)
				}
			}
		})
	}
}
