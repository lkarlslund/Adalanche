package analyze

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

// Rights an ACL grants record the ACE that grants them, by position, and
// whether it was inherited.
func TestACLEdgesRecordTheirACE(t *testing.T) {
	operatorSID := mustSID(t, "S-1-5-21-111-222-333-1200")
	readerSID := mustSID(t, "S-1-5-21-111-222-333-1201")
	target := engine.NewNode(
		engine.Name, "Target User",
		engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=Target,OU=Users,DC=example,DC=com",
	)
	graph := newADTestGraph(target)
	inherited := allowACE(operatorSID, engine.RIGHT_WRITE_DACL, uuid.Nil)
	inherited.ACEFlags = engine.ACEFLAG_INHERITED_ACE
	enginetest.Set(graph, target, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		allowACE(readerSID, engine.RIGHT_READ_CONTROL, uuid.Nil),
		allowACE(operatorSID, engine.RIGHT_WRITE_DACL, uuid.Nil),
		inherited,
	)))
	runTx(graph, addACLRuleEdges)

	operator, found := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	if !found {
		t.Fatal("operator missing")
	}
	details := map[string]bool{}
	for _, s := range graph.EdgeSources(operator, target) {
		if s.Edge != activedirectory.EdgeWriteDACL || s.Source.Kind != SourceACL || s.Source.About != nil {
			t.Fatalf("unexpected cause %+v", s)
		}
		details[s.Source.Detail] = true
	}
	if len(details) != 2 || !details["ACE 1"] || !details["ACE 2, inherited"] {
		t.Fatalf("causes %v, want ACE 1 and ACE 2, inherited", details)
	}
}

// An inherited ACE's cause leads to where it was set: the nearest ancestor
// holding it explicitly.
func TestInheritedACEOrigin(t *testing.T) {
	operatorSID := mustSID(t, "S-1-5-21-111-222-333-1200")
	ace := func(flags engine.ACEFlags) engine.ACE {
		a := allowACE(operatorSID, engine.RIGHT_WRITE_DACL, uuid.Nil)
		a.ACEFlags = flags
		return a
	}
	ou := engine.NewNode(engine.Name, "OU", engine.DistinguishedName, "OU=Users,DC=example,DC=com")
	container := engine.NewNode(engine.Name, "Container", engine.DistinguishedName, "CN=Staff,OU=Users,DC=example,DC=com")
	target := engine.NewNode(engine.Name, "Target", engine.Type, engine.NodeTypeUser.ValueString(), engine.DistinguishedName, "CN=Target,CN=Staff,OU=Users,DC=example,DC=com")
	graph := newADTestGraph(ou, container, target)
	enginetest.ChildOf(graph, container, ou)
	enginetest.ChildOf(graph, target, container)
	enginetest.Set(graph, ou, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(ace(engine.ACEFLAG_INHERIT_ACE))))
	enginetest.Set(graph, container, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(ace(engine.ACEFLAG_INHERIT_ACE|engine.ACEFLAG_INHERITED_ACE))))
	enginetest.Set(graph, target, engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(
		ace(engine.ACEFLAG_INHERITED_ACE),
		allowACE(operatorSID, engine.RIGHT_WRITE_DACL, uuid.Nil),
	)))
	runTx(graph, addACLRuleEdges)

	operator, _ := graph.Find(engine.ObjectSid, engine.NV(operatorSID))
	origins := map[string]*engine.Node{}
	for _, s := range graph.EdgeSources(operator, target) {
		origins[s.Source.Detail] = s.Source.Origin(operator, target)
	}
	if origins["ACE 0, inherited"] != ou || origins["ACE 1"] != target {
		t.Fatalf("origins %v", origins)
	}
}
