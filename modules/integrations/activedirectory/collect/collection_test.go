package collect

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
)

func TestDumpWriterFormats(t *testing.T) {
	object := activedirectory.RawObject{DistinguishedName: "CN=A", Attributes: map[string][]string{"binary": {"\x00\xff"}}}
	for _, suffix := range []string{collection.ADSuffix, ".objects.msgp.lz4"} {
		t.Run(suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test"+suffix)
			w, err := newDumpWriter(DumpOptions{WriteToFile: path, SearchBase: "DC=example,DC=test"})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Abort()
			if err := w.Write(&object); err != nil {
				t.Fatal(err)
			}
			if err := w.Commit(); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var got activedirectory.RawObject
			if suffix == collection.ADSuffix {
				r, err := collection.NewReader(f, collection.AD)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				reader := activedirectory.ObjectReader{Container: r}
				p, err := reader.Next()
				if err != nil {
					t.Fatal(err)
				}
				got = *p
				if _, err := reader.Next(); err != io.EOF {
					t.Fatal(err)
				}
			} else {
				r := msgp.NewReader(lz4.NewReader(f))
				if err := got.DecodeMsg(r); err != nil {
					t.Fatal(err)
				}
				var end activedirectory.RawObject
				if err := end.DecodeMsg(r); msgp.Cause(err) != io.EOF {
					t.Fatalf("legacy flush: %v", err)
				}
			}
			if !reflect.DeepEqual(got, object) {
				t.Fatal("object changed")
			}
		})
	}
}

func TestPolicyFilesPreserveAcquisitionResults(t *testing.T) {
	root := t.TempDir()
	want := []byte{0, 255, 128, 10}
	if err := os.WriteFile(filepath.Join(root, "policy.bin"), want, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "skipped.admx"), []byte("template"), 0600); err != nil {
		t.Fatal(err)
	}
	got := collectPolicyFiles(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{Path: "original"}}, root)
	if got.CollectionResults["enumeration"].Status != basedata.CollectionCollected {
		t.Fatal("enumeration status lost")
	}
	var found bool
	for _, file := range got.Files {
		if file.CollectionResults["security"].Status != basedata.CollectionNotRequested {
			t.Fatal("overridden security is not not_requested")
		}
		if filepath.Base(file.RelativePath) == "policy.bin" {
			found = true
			if !bytes.Equal(file.Contents, want) || file.CollectionResults["contents"].Status != basedata.CollectionCollected {
				t.Fatal("file changed")
			}
		}
		if filepath.Base(file.RelativePath) == "skipped.admx" && file.CollectionResults["contents"].Status != basedata.CollectionNotRequested {
			t.Fatal("skipped file status lost")
		}
	}
	if !found {
		t.Fatal("missing file")
	}
	missing := collectPolicyFiles(activedirectory.GPOdump{}, filepath.Join(root, "missing"))
	if missing.CollectionResults["enumeration"].Status != basedata.CollectionNotFound {
		t.Fatal("missing directory reported as collected")
	}
}
