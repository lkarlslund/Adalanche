package engine

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestAttributeValueRoundTrips(t *testing.T) {
	berlin := time.FixedZone("CET", 3600)
	sd := &SecurityDescriptor{Raw: "sd"}
	node := NewNode()
	for _, in := range []any{
		"", "alpha", true, false,
		int64(0), int64(-1), int64(math.MaxInt64), int64(math.MinInt64), uint64(math.MaxUint64),
		0.0, -2.5, math.MaxFloat64,
		time.Date(2026, 9, 29, 12, 0, 0, 500, time.UTC),          // 100ns boundary: inline
		time.Date(2026, 9, 29, 12, 0, 0, 123, time.UTC),          // sub-100ns: table
		time.Date(2026, 9, 29, 12, 0, 0, 0, berlin),              // non-UTC: table
		time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),                 // first representable tick
		time.Date(9999, 12, 31, 23, 59, 59, 999999900, time.UTC), // last inline tick
		time.Time{},
		windowssecurity.SID("S-1-5-32-544"),
		uuid.Must(uuid.NewV4()),
		sd, node,
	} {
		v := NV(in)
		if v.IsNil() {
			t.Fatalf("%T %v became nil", in, in)
		}
		got := v.Raw()
		switch want := in.(type) {
		case time.Time:
			gt := got.(time.Time)
			if !gt.Equal(want) || gt.Location().String() != want.Location().String() && !(want.Location() == time.UTC && gt.Location() == time.UTC) {
				t.Fatalf("time %v round-tripped as %v", want, gt)
			}
		case uint64:
			if got != int64(want) {
				t.Fatalf("%v round-tripped as %v", want, got)
			}
		default:
			if got != in {
				t.Fatalf("%T %v round-tripped as %T %v", in, in, got, got)
			}
		}
		if NV(in) != v {
			t.Fatalf("%T %v not deterministic", in, in)
		}
	}
}

func TestAttributeValueNil(t *testing.T) {
	var zero AttributeValue
	for _, v := range []AttributeValue{zero, NV(nil), AttributeValues{}.First(), NV((*Node)(nil)), NV((*bool)(nil))} {
		if !v.IsNil() || v.String() != "" || v.Raw() != nil {
			t.Fatalf("%+v is not the nil value", v)
		}
	}
	if NV("").IsNil() || NV(int64(0)).IsNil() || NV(false).IsNil() {
		t.Fatal("zero values are not nil")
	}
	if !NV("").IsZero() || !NV(int64(0)).IsZero() || NV("x").IsZero() {
		t.Fatal("IsZero changed meaning")
	}
}

func TestAttributeValueCompare(t *testing.T) {
	if NV(int64(math.MaxInt64)).Compare(NV(int64(math.MinInt64))) <= 0 {
		t.Fatal("large integer comparison overflowed")
	}
	a, b := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9000, 1, 1, 0, 0, 0, 0, time.UTC)
	if NV(a).Compare(NV(b)) >= 0 || NV(b).Compare(NV(a)) <= 0 {
		t.Fatal("distant time comparison overflowed")
	}
	if NV(int64(2)).Compare(NV(2.5)) >= 0 || NV(2.5).Compare(NV(int64(2))) <= 0 {
		t.Fatal("int/float comparison")
	}
}

func TestStringInternerCollisions(t *testing.T) {
	s := newStringInterner()
	a := s.intern("first")
	// Force a collision path: a second string whose hash slot is taken.
	b := s.internCollision("second")
	if s.get(a) != "first" || s.get(b) != "second" || a == b {
		t.Fatal("collision handling mixed up strings")
	}
	if s.internCollision("second") != b {
		t.Fatal("collision entry not deduplicated")
	}
}

func TestInternConcurrently(t *testing.T) {
	var wg sync.WaitGroup
	results := make([][]AttributeValue, 8)
	for w := range results {
		wg.Go(func() {
			for i := range 20000 {
				results[w] = append(results[w], NV(fmt.Sprintf("concurrent-%d", i)))
			}
		})
	}
	wg.Wait()
	for w := 1; w < len(results); w++ {
		for i := range results[w] {
			if results[w][i] != results[0][i] {
				t.Fatalf("worker %d value %d interned differently", w, i)
			}
		}
	}
	for i, v := range results[0] {
		if v.String() != fmt.Sprintf("concurrent-%d", i) {
			t.Fatalf("value %d reads back as %q", i, v.String())
		}
	}
}

func TestLowerIsCachedAndInterned(t *testing.T) {
	mixed := NVString("MiXeD-Lower-Test")
	if mixed.Lower() != NVString("mixed-lower-test") || mixed.Lower() != mixed.Lower() {
		t.Fatal("lowercase form not interned")
	}
	already := NVString("already-lower")
	if already.Lower() != already {
		t.Fatal("lowercase string should fold to itself")
	}
	if n := NVInt(7); n.Lower() != n {
		t.Fatal("non-strings are unchanged")
	}
	if NVSID("S-1-5-32-544").Lower() != NVSID("S-1-5-32-544") {
		t.Fatal("SIDs are not folded")
	}
}

func TestTypedConstructorsMatchNV(t *testing.T) {
	g := uuid.Must(uuid.NewV4())
	now := time.Now().UTC()
	for _, pair := range [][2]AttributeValue{
		{NVString("x"), NV("x")}, {NVSID("S-1-1-0"), NV(windowssecurity.SID("S-1-1-0"))},
		{NVGUID(g), NV(g)}, {NVInt(-3), NV(int64(-3))}, {NVBool(true), NV(true)}, {NVTime(now), NV(now)},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("%v != %v", pair[0], pair[1])
		}
	}
}
