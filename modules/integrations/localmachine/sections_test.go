package localmachine

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/tinylib/msgp/msgp"
)

func TestMachineInventorySections(t *testing.T) {
	info := Info{
		Machine:    Machine{Name: "test", AppCache: [][]byte{{0, 255, 1}}},
		LoginInfos: []LogonInfo{{User: "user", Count: 3}},
		Network:    NetworkInformation{InternetConnectivity: "unknown", NetworkInterfaces: []NetworkInterfaceInfo{{Name: "nic", Flags: 3}}},
		Users:      Users{{Name: "user", IsEnabled: true}}, Groups: Groups{{Name: "group", Members: []Member{{SID: "S-1-5-18"}}}},
		Shares: Shares{{Name: "share", DACL: []byte{0, 255}}}, Services: Services{{Name: "service", RegistryDACL: []byte{128, 0}}},
		Software: []Software{{DisplayName: "software"}}, Tasks: []RegisteredTask{{Name: "task", Definition: TaskDefinition{Actions: []TaskAction{{Path: "test", Args: "args"}}}}},
		Privileges:        Privileges{{Name: "privilege", AssignedSIDs: []string{"S-1-5-18"}}},
		CollectionResults: basedata.CollectionResults{"registry": {Status: basedata.CollectionAccessDenied}},
	}
	path := filepath.Join(t.TempDir(), "sections.lmc")
	if err := WriteCollection(path, info, nil); err != nil {
		t.Fatal(err)
	}
	got, _, err := ReadCollection(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.LoginInfos) != 1 || len(got.Network.NetworkInterfaces) != 1 || len(got.Users) != 1 || len(got.Groups) != 1 || len(got.Shares) != 1 || len(got.Services) != 1 || len(got.Software) != 1 || len(got.Tasks) != 1 || len(got.Privileges) != 1 {
		t.Fatal("inventory section lost")
	}
	pairs := [][2]msgp.Marshaler{
		{&info.Machine, &got.Machine}, {&info.LoginInfos[0], &got.LoginInfos[0]}, {&info.Network, &got.Network},
		{&info.Users[0], &got.Users[0]}, {&info.Groups[0], &got.Groups[0]}, {&info.Shares[0], &got.Shares[0]},
		{&info.Services[0], &got.Services[0]}, {&info.Software[0], &got.Software[0]}, {&info.Tasks[0], &got.Tasks[0]}, {&info.Privileges[0], &got.Privileges[0]},
	}
	for i, pair := range pairs {
		want, err := pair[0].MarshalMsg(nil)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := pair[1].MarshalMsg(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, want) {
			t.Fatalf("section %d changed", i)
		}
	}
	verified, err := collection.VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Header.Schema != 2 || verified.Completion.Outcome != collection.Partial {
		t.Fatal("schema or collection failure lost")
	}
}

func TestLargeMachineIsNotOneRecord(t *testing.T) {
	info := Info{Machine: Machine{Name: "test"}}
	description := strings.Repeat("x", 1<<20)
	for range 70 {
		info.Services = append(info.Services, Service{Name: "service", Description: description})
	}
	path := filepath.Join(t.TempDir(), "large.lmc")
	if err := WriteCollection(path, info, nil); err != nil {
		t.Fatal(err)
	}
	verified, err := collection.VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if verified.RecordCounts["service"] != 70 {
		t.Fatal("service inventory lost")
	}
}

func TestFirstCutMachineSchemaStillReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.lmc")
	w, err := collection.Create(path, collection.Header{Kind: collection.Machine, Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	info := Info{Machine: Machine{Name: "old"}, Users: Users{{Name: "user"}}}
	data, err := info.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write("machine", data); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(collection.Unknown); err != nil {
		t.Fatal(err)
	}
	got, _, err := ReadCollection(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Machine.Name != "old" || len(got.Users) != 1 || got.Users[0].Name != "user" {
		t.Fatal("first-cut data lost")
	}
}

func TestMissingMachineEndRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.lmc")
	w, err := collection.Create(path, collection.Header{Kind: collection.Machine, Schema: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	data, err := (&Info{}).MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write("machine", data); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(collection.Unknown); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCollection(path); err == nil {
		t.Fatal("accepted missing machine end")
	}
}

func FuzzRegistryRecord(f *testing.F) {
	seed, _ := encodeRegistryValue("key", []string{"value"})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = decodeRegistryValue(data) })
}
