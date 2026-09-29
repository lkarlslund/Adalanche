package activedirectory

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/tinylib/msgp/msgp"
)

func TestObjectCollectionRoundTrip(t *testing.T) {
	objects := []RawObject{
		{DistinguishedName: "CN=Sample,DC=example,DC=test", Attributes: map[string][]string{"objectGUID": {"\x00\xff\x80binary"}, "member;range=0-1499": {"CN=A", "CN=B"}, "custom": {"", "æøå"}}},
		{DistinguishedName: "", Attributes: map[string][]string{"defaultNamingContext": {"DC=example,DC=test"}, "custom": {"second"}}},
	}
	path := filepath.Join(t.TempDir(), "objects.adc")
	w, err := collection.Create(path, collection.Header{Kind: collection.AD, Schema: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	writer := ObjectWriter{Container: w}
	for i := range objects {
		if err := writer.Write(&objects[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Commit("complete"); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := collection.NewReader(f, collection.AD)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reader := ObjectReader{Container: r}
	for _, want := range objects {
		got, err := reader.Next()
		if err != nil || !reflect.DeepEqual(got, &want) {
			t.Fatalf("got %+v, want %+v; %v", got, want, err)
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatal(err)
	}
	if len(reader.attributes) != 4 {
		t.Fatalf("dictionary has %d definitions, want 4", len(reader.attributes))
	}
}

func TestObjectDecoderRejectsInvalidReferences(t *testing.T) {
	r := ObjectReader{attributes: []string{"name"}}
	for _, id := range []uint32{1, ^uint32(0)} {
		payload := msgp.AppendString(nil, "dn")
		payload = msgp.AppendMapHeader(payload, 1)
		payload = msgp.AppendUint32(payload, id)
		payload = msgp.AppendArrayHeader(payload, 0)
		if _, err := r.decode(payload, true); err == nil {
			t.Fatalf("accepted attribute %d", id)
		}
	}
}

func TestPolicyCollectionRoundTrip(t *testing.T) {
	sid, err := windowssecurity.ParseStringSID("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	info := GPOdump{Common: basedata.Common{Collected: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}, GPOinfo: GPOinfo{
		GUID: uuid.Must(uuid.FromString("11111111-2222-3333-4444-555555555555")), Path: "policy", DomainDN: "DC=example,DC=test",
		CollectionResults: basedata.CollectionResults{"enumeration": {Status: basedata.CollectionCollected}},
		Files: []GPOfileinfo{{RelativePath: "/binary", OwnerSID: sid, DACL: []byte{0, 128, 255}, Contents: []byte{0, 255, 128, 10}, Size: 4,
			CollectionResults: basedata.CollectionResults{"contents": {Status: basedata.CollectionCollected}, "security": {Status: basedata.CollectionAccessDenied, ErrorCode: "errno:5"}}}},
	}}
	for _, suffix := range []string{collection.GPOSuffix, ".gpodata.json"} {
		t.Run(suffix, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy"+suffix)
			if suffix == collection.GPOSuffix {
				err = WriteGPOCollection(path, info)
			} else {
				var data []byte
				data, err = json.Marshal(info)
				if err == nil {
					err = os.WriteFile(path, data, 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadGPOCollection(path)
			if err != nil || !reflect.DeepEqual(got, info) {
				t.Fatalf("roundtrip: got %+v, want %+v; %v", got, info, err)
			}
			if suffix == collection.GPOSuffix {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				r, err := collection.NewReader(bytes.NewReader(data), collection.GPO)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				for {
					_, _, err := r.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if r.Completion.Outcome != "partial" {
					t.Fatalf("outcome = %s", r.Completion.Outcome)
				}
				if err := os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
					t.Fatal(err)
				}
				if got, err := ReadGPOCollection(path); err == nil || len(got.Files) != 0 {
					t.Fatal("returned interrupted policy data")
				}
			}
		})
	}
}

func FuzzObjectPayload(f *testing.F) {
	f.Add(msgp.AppendMapHeader(msgp.AppendString(nil, "dn"), 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := ObjectReader{attributes: []string{"name"}}
		_, decoded := r.decode(data, true)
		_, validated := r.decode(data, false)
		if (decoded == nil) != (validated == nil) {
			t.Fatal("validation and decoding disagree")
		}
	})
}
