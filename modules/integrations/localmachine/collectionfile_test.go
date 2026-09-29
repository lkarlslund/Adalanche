package localmachine

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/collection"
)

func TestMachineCollection(t *testing.T) {
	info := Info{Machine: Machine{Name: "TEST-PC", Domain: "example.test", IsDomainJoined: true},
		RegistryData:                            RegistryData{"zero": uint64(0), "maximum": ^uint64(0), "signed": int64(-1), "empty": "", "binary": []byte{0, 255}, "strings": []string{"a", "b"}},
		CollectionResults:                       basedata.CollectionResults{"registry/denied": {Status: basedata.CollectionAccessDenied, ErrorCode: "errno:5"}},
		ServiceControlManagerSecurityDescriptor: []byte{0, 128, 255},
	}
	extensions := map[string][]byte{"extension:test/v1": {0, 255, 1}}
	path := filepath.Join(t.TempDir(), "machine"+collection.MachineSuffix)
	if err := WriteCollection(path, info, extensions); err != nil {
		t.Fatal(err)
	}
	got, extra, err := ReadCollection(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.RegistryData, info.RegistryData) || !reflect.DeepEqual(got.CollectionResults, info.CollectionResults) || !reflect.DeepEqual(extra, extensions) || !reflect.DeepEqual(got.Machine, info.Machine) {
		t.Fatalf("machine data changed: registry got %#v want %#v; results got %#v want %#v; extensions got %#v want %#v; machine got %#v want %#v", got.RegistryData, info.RegistryData, got.CollectionResults, info.CollectionResults, extra, extensions, got.Machine, info.Machine)
	}
	if !bytes.Equal(got.ServiceControlManagerSecurityDescriptor, info.ServiceControlManagerSecurityDescriptor) {
		t.Fatal("descriptor changed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if got, _, err := ReadCollection(path); err == nil || got.Machine.Name != "" {
		t.Fatal("returned incomplete machine data")
	}
}
