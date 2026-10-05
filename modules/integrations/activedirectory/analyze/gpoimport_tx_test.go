package analyze

import (
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func utf16LE(s string) []byte {
	b := []byte{0xff, 0xfe}
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

// A policy import builds the folder tree, script nodes and membership edges
// in one transaction.
func TestGPOImportBuildsTreeInOneTransaction(t *testing.T) {
	graph := newADTestGraph()
	guid := uuid.Must(uuid.FromString("0f0e0d0c-0b0a-4908-8706-050403020100"))
	const groups = `<Groups><Group name="Administrators (built-in)"><Properties action="U" groupSid="S-1-5-32-544"><Members><Member name="X\someone" action="ADD" sid="S-1-5-21-1-2-3-1105"/></Members></Properties></Group></Groups>`
	err := ImportGPOInfo(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{
		GUID: guid,
		Path: "/synthetic/policy",
		Files: []activedirectory.GPOfileinfo{
			{RelativePath: "/", IsDir: true},
			{RelativePath: "/Machine", IsDir: true},
			{RelativePath: "/Machine/Scripts", IsDir: true},
			{RelativePath: "/Machine/Scripts/scripts.ini", Contents: utf16LE("[Startup]\r\n0CmdLine=start.cmd\r\n0Parameters=\r\n[Shutdown]\r\n0CmdLine=stop.cmd\r\n0Parameters=\r\n")},
			{RelativePath: "/Machine/Preferences/Groups/Groups.xml", Contents: []byte(groups)},
		},
	}}, graph)
	if err != nil {
		t.Fatal(err)
	}

	gpo, found := graph.Find(gPCFileSysPath, engine.NV("/synthetic/policy"))
	if !found {
		t.Fatal("policy node missing")
	}
	path := func(p string) *engine.Node {
		t.Helper()
		nodes, found := graph.FindMulti(AbsolutePath, engine.NV(p))
		if !found || nodes.Len() != 1 {
			t.Fatalf("want one node for %v, got %v", p, nodes.Len())
		}
		return nodes.First()
	}
	root := path("/synthetic/policy")
	machine := path("/synthetic/policy/machine")
	scripts := path("/synthetic/policy/machine/scripts")
	ini := path("/synthetic/policy/machine/scripts/scripts.ini")
	for _, link := range []struct{ child, parent *engine.Node }{{root, gpo}, {machine, root}, {scripts, machine}, {ini, scripts}} {
		if link.child.Parent() != link.parent {
			t.Errorf("%v: parent %v, want %v", link.child.Label(), link.child.Parent(), link.parent.Label())
		}
		requireEdgeSet(t, graph, link.child, link.parent, EdgeFSPartOfGPO)
	}

	var scriptNodes int
	graph.Iterate(func(o *engine.Node) bool {
		if strings.HasPrefix(o.OneAttrString(engine.Name), "Machine ") {
			scriptNodes++
			if o.Parent() != gpo {
				t.Errorf("script %v is not under the policy", o.Label())
			}
			requireEdgeSet(t, graph, o, gpo, activedirectory.EdgeMachineScript)
		}
		return true
	})
	if scriptNodes != 2 {
		t.Errorf("got %v script nodes, want 2", scriptNodes)
	}

	member, found := graph.Find(activedirectory.ObjectSid, engine.NVSID(windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1105")))
	if !found {
		t.Fatal("member node missing")
	}
	// The grant is kept on the policy; it becomes rights on the machines the
	// policy applies to once those are known.
	requireNoEdgeSet(t, graph, member, gpo, activedirectory.EdgeLocalAdminRights)
	if grants := gpo.Attr(GPOLocalGroupMemberSID).StringSlice(); len(grants) != 1 || grants[0] != "S-1-5-32-544|S-1-5-21-1-2-3-1105|"+gpoGroupPreference {
		t.Fatalf("recorded grants %v", grants)
	}
}

// A policy whose import fails adds nothing to the graph.
func TestFailedGPOImportAddsNothing(t *testing.T) {
	graph := newADTestGraph()
	before := graph.Order()
	err := ImportGPOInfo(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{
		Path: "/synthetic/broken",
		Files: []activedirectory.GPOfileinfo{
			{RelativePath: "/", IsDir: true},
			{RelativePath: "/credentials.xml", Contents: []byte(`<Properties cpassword="x" account="y" />`)},
		},
	}}, graph)
	if err == nil {
		t.Fatal("import of an unrecognized credential entry succeeded")
	}
	if graph.Order() != before {
		t.Errorf("failed import added %v nodes", graph.Order()-before)
	}
}

// Exposed passwords are nodes of their own under the file they were found
// in. They do not carry the GPO's GUID, so they never merge with the GPO or
// with each other.
func TestExposedPasswordsStayUnderTheirFile(t *testing.T) {
	guid := uuid.Must(uuid.FromString("0f0e0d0c-0b0a-4908-8706-050403020100"))
	graph := func() *engine.IndexedGraph {
		g := newADTestGraph()
		if err := ImportGPOInfo(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{
			GUID: guid,
			Path: "/synthetic/policy",
			Files: []activedirectory.GPOfileinfo{
				{RelativePath: "/", IsDir: true},
				{RelativePath: "/a.xml", Contents: []byte(`<Properties cpassword="one" userName="u1" />` + "\n" + `<Properties cpassword="two" userName="u2" />`)},
				{RelativePath: "/b.xml", Contents: []byte(`<Properties cpassword="three" userName="u3" />`)},
			},
		}}, g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := graph()
	for _, secret := range []string{"one", "two", "three"} {
		exposed, found := g.Find(ExposedPassword, engine.NV(secret))
		if !found {
			t.Fatalf("exposed password %v missing", secret)
		}
		if exposed.HasAttr(engine.ObjectGUID) {
			t.Error("exposed password carries the GPO's GUID")
		}
		if exposed.Parent() == nil || exposed.Parent().OneAttrString(RelativePath) != exposed.OneAttrString(RelativePath) {
			t.Error("exposed password not under its file")
		}
	}
	merged := enginetest.Load(g, graph())
	if exposed, _ := merged.FindMulti(engine.Type, engine.NV("ExposedPassword")); exposed.Len() != 6 {
		t.Errorf("got %v exposed passwords after merging two copies, want 6", exposed.Len())
	}
}

// A GPO collection resolves to the directory's GPO object by domain and
// GUID, whatever server its path names, and builtin owners in it are those
// of the GPO's own domain.
func TestGPOCollectionResolvesToItsDomain(t *testing.T) {
	const guid = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	dn := "CN=" + guid + ",CN=Policies,CN=System,DC=b,DC=test"
	directory := engine.NewIndexedGraph()
	adminsA := engine.NewNode(engine.Name, "Administrators", engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.ObjectSid, engine.NVSID(windowssecurity.AdministratorsSID), engine.DomainContext, "DC=a,DC=test", engine.DataSource, "A")
	adminsB := engine.NewNode(engine.Name, "Administrators", engine.Type, engine.NodeTypeGroup.ValueString(),
		engine.ObjectSid, engine.NVSID(windowssecurity.AdministratorsSID), engine.DomainContext, "DC=b,DC=test", engine.DataSource, "B")
	gpo := engine.NewNode(engine.DistinguishedName, dn, engine.Type, engine.NodeTypeGroupPolicyContainer.ValueString(),
		engine.DataSource, "B", engine.DomainContext, "DC=b,DC=test", activedirectory.GPOIdentity, activedirectory.GPOIdentityFromDN(dn))
	enginetest.Add(directory, adminsA, adminsB, gpo)

	collected := engine.NewIndexedGraph()
	if err := ImportGPOInfo(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{
		Path: `\\dc07.b.test\SysVol\b.test\Policies\` + guid,
		Files: []activedirectory.GPOfileinfo{
			{RelativePath: "/", IsDir: true, OwnerSID: windowssecurity.AdministratorsSID},
		},
	}}, collected); err != nil {
		t.Fatal(err)
	}

	merged := enginetest.Load(directory, collected)
	gpos, _ := merged.FindMulti(activedirectory.GPOIdentity, engine.NV(activedirectory.GPOIdentityFromDN(dn)))
	if gpos.Len() != 1 || gpos.First() != gpo {
		t.Fatalf("got %v GPO nodes, want the collection folded into the directory's", gpos.Len())
	}
	folder, found := merged.Find(AbsolutePath, engine.NV(`\\dc07.b.test\SysVol\b.test\Policies\`+guid))
	if !found {
		t.Fatal("GPO folder missing")
	}
	if eb, _ := merged.GetEdge(adminsB, folder); !eb.IsSet(EdgeOwns) {
		t.Error("the folder's owner is not the GPO domain's Administrators")
	}
	if eb, _ := merged.GetEdge(adminsA, folder); eb.IsSet(EdgeOwns) {
		t.Error("another domain's Administrators owns the folder")
	}
}
