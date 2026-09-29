package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

func TestADCollectionValidationBeforeImport(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "test.adc")
		w, err := collection.Create(path, collection.Header{Kind: collection.AD, Schema: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer w.Abort()
		objects := activedirectory.ObjectWriter{Container: w}
		if err := objects.Write(&activedirectory.RawObject{DistinguishedName: "CN=A", Attributes: map[string][]string{"objectClass": {"user"}}}); err != nil {
			t.Fatal(err)
		}
		if invalid {
			if err := w.Write("unsupported", []byte("test")); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Commit("complete"); err != nil {
			t.Fatal(err)
		}
		ld := ADLoader{objectstoconvert: make(chan convertqueueitem, 4)}
		err = ld.Load(path, func(int, int) {})
		if invalid {
			if err == nil || len(ld.objectstoconvert) != 0 {
				t.Fatal("invalid collection admitted to analysis")
			}
		} else {
			if err != nil || len(ld.objectstoconvert) != 1 {
				t.Fatalf("valid collection: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
				t.Fatal(err)
			}
			ld.objectstoconvert = make(chan convertqueueitem, 4)
			if err := ld.Load(path, func(int, int) {}); err == nil || len(ld.objectstoconvert) != 0 {
				t.Fatal("interrupted collection admitted to analysis")
			}
		}
	}
}
