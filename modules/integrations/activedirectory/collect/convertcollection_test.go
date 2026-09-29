package collect

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

func TestLegacyObjectConversion(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "old.objects.msgp.lz4")
	target := filepath.Join(dir, "new.adc")
	objects := []activedirectory.RawObject{
		{DistinguishedName: "CN=A", Attributes: map[string][]string{"objectGUID": {"\x00\xff\x80"}, "custom": {"", "text"}}},
		{DistinguishedName: "CN=B", Attributes: map[string][]string{"member;range=0-1499": {"CN=A"}}},
	}
	w, err := newDumpWriter(DumpOptions{WriteToFile: source})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	for i := range objects {
		if err := w.Write(&objects[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := collection.ConvertFile(source, target); err != nil {
		t.Fatal(err)
	}
	verified, err := collection.VerifyFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Completion.Outcome != collection.Unknown {
		t.Fatal("conversion invented acquisition coverage")
	}
	f, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := collection.NewReader(f, collection.AD)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reader := activedirectory.ObjectReader{Container: r}
	for _, want := range objects {
		got, err := reader.Next()
		if err != nil || !reflect.DeepEqual(got, &want) {
			t.Fatalf("conversion changed object: %v", err)
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatal(err)
	}
	if err := collection.ConvertFile(source, target); err == nil {
		t.Fatal("conversion overwrote existing target")
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, raw[:len(raw)-1], 0600); err != nil {
		t.Fatal(err)
	}
	badTarget := filepath.Join(dir, "bad.adc")
	if err := collection.ConvertFile(source, badTarget); err == nil {
		t.Fatal("accepted truncated legacy input")
	}
	if _, err := os.Stat(badTarget); !os.IsNotExist(err) {
		t.Fatal("published failed conversion")
	}
}
