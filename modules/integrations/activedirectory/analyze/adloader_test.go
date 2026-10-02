package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func wireSID(t *testing.T, s string) string {
	sid, err := windowssecurity.ParseStringSID(s)
	if err != nil {
		t.Fatal(err)
	}
	return string([]byte{1, byte(sid.Components() - 2)}) + string(sid)
}

func writeADCollection(t *testing.T, path string, objects ...*activedirectory.RawObject) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	w, err := collection.Create(path, collection.Header{Kind: collection.AD, Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	ow := activedirectory.ObjectWriter{Container: w}
	for _, o := range objects {
		if err := ow.Write(o); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Commit("complete"); err != nil {
		t.Fatal(err)
	}
}

func syntheticDomain(t *testing.T, dn, netbios, sid string) []*activedirectory.RawObject {
	return []*activedirectory.RawObject{
		{DistinguishedName: dn, Attributes: map[string][]string{
			"objectClass": {"top", "domain", "domainDNS"},
			"objectSid":   {wireSID(t, sid)},
		}},
		{DistinguishedName: "CN=" + netbios + ",CN=Partitions,CN=Configuration," + dn, Attributes: map[string][]string{
			"objectClass": {"top", "crossRef"},
			"nCName":      {dn},
			"nETBIOSName": {netbios},
		}},
		{DistinguishedName: "CN=Someone,CN=Users," + dn, Attributes: map[string][]string{
			"objectClass": {"top", "person", "user"},
			"objectSid":   {wireSID(t, sid+"-1105")},
		}},
	}
}

// The AD loader stages each folder's objects in a transaction and commits it
// on Close, marking every object with the domain it was collected from.
func TestADLoaderCommitsShardsWithDataSource(t *testing.T) {
	dir := t.TempDir()
	domains := map[string]string{"ONE": "DC=one,DC=test", "TWO": "DC=two,DC=test"}
	sids := map[string]string{"ONE": "S-1-5-21-1-2-3", "TWO": "S-1-5-21-4-5-6"}
	for nb, dn := range domains {
		writeADCollection(t, filepath.Join(dir, nb, "objects.adc"), syntheticDomain(t, dn, nb, sids[nb])...)
	}

	var ld ADLoader
	if err := ld.Init(); err != nil {
		t.Fatal(err)
	}
	for nb := range domains {
		if err := ld.Load(filepath.Join(dir, nb, "objects.adc"), func(int, int) {}); err != nil {
			t.Fatal(err)
		}
	}
	graphs, err := ld.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(graphs) != 2 {
		t.Fatalf("got %v graphs, want 2", len(graphs))
	}
	for _, g := range graphs {
		var source string
		count := 0
		g.Iterate(func(o *engine.Node) bool {
			count++
			ds := o.OneAttrString(engine.DataSource)
			if source == "" {
				source = ds
			}
			if ds == "" || ds != source {
				t.Errorf("node %v has data source %q, want %q", o.Label(), ds, source)
			}
			return true
		})
		if count != 4 { // root plus three objects
			t.Errorf("graph has %v nodes, want 4", count)
		}
		dn, found := domains[source]
		if !found {
			t.Fatalf("unexpected data source %q", source)
		}
		user, found := g.Find(engine.DistinguishedName, engine.NV("CN=Someone,CN=Users,"+dn))
		if !found {
			t.Fatal("user not found by DN after commit")
		}
		if user.SID().String() != sids[source]+"-1105" {
			t.Errorf("user SID %v", user.SID())
		}
		if got, found := g.Find(engine.ObjectSid, engine.NVSID(user.SID())); !found || got != user {
			t.Error("user not found by SID after commit")
		}
	}
}
