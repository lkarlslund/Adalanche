package aql

import "testing"

func TestNewResolverOptionsIsBounded(t *testing.T) {
	if got := NewResolverOptions().NodeLimit; got != DefaultNodeLimit || got <= 0 {
		t.Fatalf("default NodeLimit = %d, want a positive %d so bare callers are bounded", got, DefaultNodeLimit)
	}
}

func TestEffectiveNodeLimit(t *testing.T) {
	for _, tt := range []struct{ in, want int }{
		{0, HardNodeCeiling},                   // no limit -> hard ceiling
		{-1, HardNodeCeiling},                  // explicit unlimited -> hard ceiling
		{HardNodeCeiling + 1, HardNodeCeiling}, // above ceiling -> clamped
		{5000, 5000},                           // within range -> kept
		{HardNodeCeiling, HardNodeCeiling},
	} {
		if got := effectiveNodeLimit(tt.in); got != tt.want {
			t.Errorf("effectiveNodeLimit(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
