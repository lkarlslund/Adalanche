package engine

import (
	"testing"
	"time"
)

func TestNVSupportsCoreTypesAndDeduplicatesStrings(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name string
		in   any
	}{
		{name: "string", in: "alpha"},
		{name: "bool", in: true},
		{name: "int", in: int64(42)},
		{name: "float", in: 4.2},
		{name: "time", in: now},
		{name: "node", in: testNamedNode("embedded")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := NV(tt.in)
			if value == nil {
				t.Fatal("expected normalized value")
			}
		})
	}

	if NV("alpha") != NV("alpha") {
		t.Fatal("expected string normalization to deduplicate equal values")
	}
}

func TestCompareAttributeValuesAcrossTypes(t *testing.T) {
	if !CompareAttributeValues(NV("alpha"), NV("ALPHA")) {
		t.Fatal("expected string compare to be case-insensitive")
	}
	if CompareAttributeValues(NV(int64(1)), NV(int64(2))) {
		t.Fatal("expected different ints not to compare equal")
	}
	if CompareAttributeValuesInt(NV(int64(1)), NV(int64(2))) >= 0 {
		t.Fatal("expected ordered comparison for ints")
	}
}

func TestNVPanicsOnUnsupportedType(t *testing.T) {
	requirePanic(t, func() {
		NV(struct{}{})
	})
}
