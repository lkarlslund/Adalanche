package localmachine

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/tinylib/msgp/msgp"
)

func TestCollectionResultsSerialization(t *testing.T) {
	info := Info{RegistryData: RegistryData{"zero": uint64(0), "empty": ""}, CollectionResults: basedata.CollectionResults{
		"registry/value/zero":    {Status: basedata.CollectionCollected},
		"registry/value/denied":  {Status: basedata.CollectionAccessDenied, ErrorCode: "errno:5"},
		"registry/value/missing": {Status: basedata.CollectionNotFound},
	}}
	for _, format := range []string{"json", "msgpack", "stream"} {
		t.Run(format, func(t *testing.T) {
			var decoded Info
			switch format {
			case "json":
				raw, err := json.Marshal(info)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &decoded); err != nil {
					t.Fatal(err)
				}
			case "msgpack":
				raw, err := info.MarshalMsg(nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := decoded.UnmarshalMsg(raw); err != nil {
					t.Fatal(err)
				}
			case "stream":
				var b bytes.Buffer
				if err := msgp.Encode(&b, &info); err != nil {
					t.Fatal(err)
				}
				if err := msgp.Decode(&b, &decoded); err != nil {
					t.Fatal(err)
				}
			}
			if decoded.CollectionResults["registry/value/denied"] != info.CollectionResults["registry/value/denied"] {
				t.Fatal("outcome lost")
			}
			if decoded.CollectionResults["registry/value/missing"].Status != basedata.CollectionNotFound {
				t.Fatal("absence lost")
			}
			if _, ok := decoded.RegistryData["zero"]; !ok {
				t.Fatal("zero lost")
			}
			if _, ok := decoded.RegistryData["empty"]; !ok {
				t.Fatal("empty value lost")
			}
		})
	}
}

func TestLegacyCollectionHasUnknownOutcomes(t *testing.T) {
	var info Info
	if err := json.Unmarshal([]byte(`{"RegistryData":{"zero":0}}`), &info); err != nil {
		t.Fatal(err)
	}
	if info.CollectionResults["registry/value/zero"].Status != basedata.CollectionUnknown {
		t.Fatal("fabricated legacy result")
	}
	// A historical one-field map, with no new acquisition metadata.
	raw := msgp.AppendMapHeader(nil, 1)
	raw = msgp.AppendString(raw, "RegistryData")
	raw = msgp.AppendMapHeader(raw, 1)
	raw = msgp.AppendString(raw, "zero")
	raw = msgp.AppendUint64(raw, 0)
	var decoded Info
	if _, err := decoded.UnmarshalMsg(raw); err != nil {
		t.Fatal(err)
	}
	if decoded.CollectionResults["registry/value/zero"].Status != basedata.CollectionUnknown {
		t.Fatal("fabricated legacy result")
	}
}
