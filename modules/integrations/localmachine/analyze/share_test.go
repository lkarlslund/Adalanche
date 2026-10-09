package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestShareDirectoryUsesRawACL(t *testing.T) {
	g := engine.NewIndexedGraph()
	info := benchmarkCollectorInfo()
	sid := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1001")
	acl := serviceTestACL(engine.ACE{Type: engine.ACETYPE_ACCESS_ALLOWED, SID: sid, Mask: engine.FILE_WRITE_DATA})
	info.Shares = []lm.Share{{Name: "synthetic", Path: `C:\synthetic`, DACL: serviceTestDescriptor(windowssecurity.SystemSID, acl), PathDACL: acl, PathOwner: windowssecurity.SystemSID.String()}}
	machine, err := importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	path, ok := g.FindTwo(AbsolutePath, engine.NV(`C:\synthetic`), engine.Type, engine.NV("Directory"))
	if !ok {
		t.Fatal("missing share directory")
	}
	user, ok := g.FindAdjacentSID(sid, machine)
	if !ok {
		t.Fatal("missing trustee")
	}
	edges, _ := g.GetEdge(user, path)
	if !edges.IsSet(EdgeFileWrite) {
		t.Fatal("directory ACL was not analyzed")
	}
}
