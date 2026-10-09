package mcpserver

import (
	"strings"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var edgeWritesMember = engine.NewEdge("MCPTestWritesMember")

func mustSID(t *testing.T, s string) windowssecurity.SID {
	t.Helper()
	sid, err := windowssecurity.ParseStringSID(s)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// aclGraph: an OU grants helpdesk WriteProperty on member to descendant
// groups; the group below it inherits that ACE after an explicit deny for
// Everyone, and helpdesk has an edge into the group caused by it.
func aclGraph(t *testing.T) (*engine.IndexedGraph, map[string]*engine.Node) {
	t.Helper()
	helpdeskSID := mustSID(t, "S-1-5-21-1-2-3-1105")
	everyone := mustSID(t, "S-1-1-0")
	memberGUID := uuid.Must(uuid.FromString("bf9679c0-0de6-11d0-a285-00aa003049e2"))
	groupClassGUID := uuid.Must(uuid.FromString("bf967a9c-0de6-11d0-a285-00aa003049e2"))

	writeMember := engine.ACE{
		Type:                engine.ACETYPE_ACCESS_ALLOWED_OBJECT,
		ACEFlags:            engine.ACEFLAG_INHERIT_ACE | engine.ACEFLAG_INHERIT_ONLY_ACE,
		Flags:               engine.OBJECT_TYPE_PRESENT | engine.INHERITED_OBJECT_TYPE_PRESENT,
		Mask:                engine.RIGHT_DS_WRITE_PROPERTY,
		SID:                 helpdeskSID,
		ObjectType:          memberGUID,
		InheritedObjectType: groupClassGUID,
	}
	inherited := writeMember
	inherited.ACEFlags = engine.ACEFLAG_INHERITED_ACE
	deny := engine.ACE{Type: engine.ACETYPE_ACCESS_DENIED, Mask: engine.RIGHT_DELETE | engine.RIGHT_DS_DELETE_TREE, SID: everyone}

	nodes := map[string]*engine.Node{
		"ou":       engine.NewNode(engine.Name, "Servers", engine.DistinguishedName, "OU=Servers,DC=example,DC=test"),
		"group":    engine.NewNode(engine.Name, "Server Admins", engine.DistinguishedName, "CN=Server Admins,OU=Servers,DC=example,DC=test"),
		"helpdesk": engine.NewNode(engine.Name, "Helpdesk", engine.ObjectSid, helpdeskSID),
		"member": engine.NewNode(engine.Name, "member", engine.LDAPDisplayName, "member",
			engine.SchemaIDGUID, memberGUID, engine.ObjectClass, "attributeSchema"),
		"groupclass": engine.NewNode(engine.Name, "Group", engine.LDAPDisplayName, "group",
			engine.SchemaIDGUID, groupClassGUID, engine.ObjectClass, "classSchema"),
	}
	g := engine.NewIndexedGraph()
	for _, n := range nodes {
		enginetest.Add(g, n)
	}
	enginetest.ChildOf(g, nodes["group"], nodes["ou"])
	enginetest.Set(g, nodes["ou"], engine.NTSecurityDescriptor, engine.NV(&engine.SecurityDescriptor{
		Control: engine.CONTROLFLAG_DACL_PRESENT, DACL: engine.ACL{Entries: []engine.ACE{writeMember}},
	}))
	enginetest.Set(g, nodes["group"], engine.NTSecurityDescriptor, engine.NV(&engine.SecurityDescriptor{
		Control: engine.CONTROLFLAG_DACL_PRESENT, Owner: helpdeskSID, DACL: engine.ACL{Entries: []engine.ACE{deny, inherited}},
	}))
	enginetest.Update(g, func(tx *engine.Tx) {
		tx.EdgeBecause(nodes["helpdesk"], nodes["group"], edgeWritesMember, engine.Source{Kind: testCause, Detail: "ACE 1, inherited"})
	})
	return g, nodes
}

func TestGetACL(t *testing.T) {
	g, nodes := aclGraph(t)
	session := connect(t, fixedSource{g, frontend.Ready})
	group := idOf(t, session, nodes["group"])

	var out aclOutput
	if msg := call(t, session, "get_acl", map[string]any{"id": group}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Total != 2 || len(out.ACEs) != 2 {
		t.Fatalf("got %d ACEs", out.Total)
	}
	if out.Owner == nil || out.Owner.Node == nil || out.Owner.Node.Label != "Helpdesk" {
		t.Errorf("owner %+v", out.Owner)
	}

	deny := out.ACEs[0]
	if deny.Access != "deny" || deny.Trustee.Name != "Everyone" || strings.Join(deny.Rights, ",") != "DeleteTree,Delete" {
		t.Errorf("deny ACE: %+v", deny)
	}
	if deny.Scope != "this object" || deny.SetOn == nil || deny.SetOn.Label != "Server Admins" {
		t.Errorf("deny scope %q, set on %+v", deny.Scope, deny.SetOn)
	}

	ace := out.ACEs[1]
	if ace.Access != "allow" || ace.Trustee.Node == nil || ace.Trustee.Node.Label != "Helpdesk" {
		t.Errorf("trustee: %+v", ace.Trustee)
	}
	if ace.ObjectType == nil || ace.ObjectType.Name != "member" || ace.ObjectType.Kind != "property" {
		t.Errorf("object type: %+v", ace.ObjectType)
	}
	if ace.AppliesTo == nil || ace.AppliesTo.Name != "group" || ace.AppliesTo.Kind != "class" {
		t.Errorf("applies to: %+v", ace.AppliesTo)
	}
	if !ace.Inherited || ace.SetOn == nil || ace.SetOn.Label != "Servers" {
		t.Errorf("inherited %v from %+v", ace.Inherited, ace.SetOn)
	}
	if len(ace.Edges) != 1 || ace.Edges[0].From.Label != "Helpdesk" || ace.Edges[0].EdgeTypes[0] != edgeWritesMember.String() {
		t.Errorf("edges: %+v", ace.Edges)
	}
	want := "ACE 1: Allow Helpdesk WriteProperty limited to property member, on this object of class group; inherited from Servers"
	if ace.Summary != want {
		t.Errorf("summary:\n got %s\nwant %s", ace.Summary, want)
	}

	var one aclOutput
	if msg := call(t, session, "get_acl", map[string]any{"id": group, "ace": 1}, &one); msg != "" || len(one.ACEs) != 1 || one.ACEs[0].Index != 1 {
		t.Errorf("ace filter: %s %+v", msg, one.ACEs)
	}
	var byTrustee aclOutput
	if msg := call(t, session, "get_acl", map[string]any{"id": group, "trustee": "S-1-1-0"}, &byTrustee); msg != "" || byTrustee.Total != 1 || byTrustee.ACEs[0].Index != 0 {
		t.Errorf("trustee filter: %s %+v", msg, byTrustee.ACEs)
	}
	if msg := call(t, session, "get_acl", map[string]any{"id": group, "ace": 7}, &one); !strings.Contains(msg, "no ACE 7") {
		t.Errorf("missing ACE: %q", msg)
	}

	// The cause on the route points at the ACE.
	var path pathOutput
	if msg := call(t, session, "get_edge_path_details", map[string]any{"node_ids": []string{idOf(t, session, nodes["helpdesk"]), group}}, &path); msg != "" {
		t.Fatal(msg)
	}
	cause := path.Steps[0].EdgeTypes[0].Causes[0]
	if cause.ACE == nil || *cause.ACE != 1 || cause.ACEAttribute != "" {
		t.Errorf("cause: %+v", cause)
	}
}

func TestCauseACE(t *testing.T) {
	for _, tt := range []struct {
		detail string
		attr   string
		index  int
		ok     bool
	}{
		{"ACE 45", "nTSecurityDescriptor", 45, true},
		{"ACE 45, inherited", "nTSecurityDescriptor", 45, true},
		{"file ACE 3", "nTSecurityDescriptor", 3, true},
		{"msDS-GroupMSAMembership ACE 3", "msDS-GroupMSAMembership", 3, true},
		{"owner", "", 0, false},
		{"read property and control access", "", 0, false},
	} {
		attr, index, ok := causeACE(tt.detail)
		if ok != tt.ok || (ok && (attr != tt.attr || index != tt.index)) {
			t.Errorf("%q: got %q %d %v", tt.detail, attr, index, ok)
		}
	}
}
