package activedirectory

import (
	"testing"

	"github.com/tinylib/msgp/msgp"
)

func validationPayload() []byte {
	payload := msgp.AppendString(nil, "CN=Sample,DC=example,DC=test")
	payload = msgp.AppendMapHeader(payload, 2)
	for id := range uint32(2) {
		payload = msgp.AppendUint32(payload, id)
		payload = msgp.AppendArrayHeader(payload, 2)
		payload = msgp.AppendBytes(payload, []byte("sample"))
		payload = msgp.AppendBytes(payload, []byte{0, 128, 255})
	}
	return payload
}

func TestObjectValidationMatchesDecode(t *testing.T) {
	payload := validationPayload()
	r := ObjectReader{attributes: []string{"name", "binary"}}
	for n := 0; n <= len(payload); n++ {
		_, decoded := r.decode(payload[:n], true)
		_, validated := r.decode(payload[:n], false)
		if (decoded == nil) != (validated == nil) {
			t.Fatalf("validation mismatch at length %d", n)
		}
	}
	// Two IDs naming the same attribute must be rejected in either mode.
	r.attributes[1] = "name"
	for _, retain := range []bool{true, false} {
		if _, err := r.decode(payload, retain); err == nil {
			t.Fatal("duplicate name accepted")
		}
	}
	r.attributes[1] = "binary"
	allocs := testing.AllocsPerRun(100, func() {
		object, err := r.decode(payload, false)
		if err != nil || object != nil {
			t.Fatal("validation retained an object or failed")
		}
	})
	if allocs != 0 {
		t.Fatalf("validation allocates %v times per object", allocs)
	}
}

func BenchmarkObjectPayload(b *testing.B) {
	payload := validationPayload()
	for _, tc := range []struct {
		name   string
		retain bool
	}{{"decode", true}, {"validate", false}} {
		b.Run(tc.name, func(b *testing.B) {
			r := ObjectReader{attributes: []string{"name", "binary"}}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := r.decode(payload, tc.retain); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
