package engine

import "testing"

func TestAttributesAndValuesMergeDeduplicatesAndHonorsDropWhenMerging(t *testing.T) {
	dropAttr := NewAttribute("unit-test-drop-attr").Flag(DropWhenMerging)
	var left, right AttributesAndValues
	left.init()
	right.init()
	left.Set(Name, AttributeValues{NV("Alpha")})
	left.Set(dropAttr, AttributeValues{NV("left-only")})
	right.Set(Name, AttributeValues{NV("Alpha")})
	right.Set(DisplayName, AttributeValues{NV("Display")})
	right.Set(dropAttr, AttributeValues{NV("right-only")})

	merged := left.Merge(&right)

	if got, found := merged.Get(Name); !found || got.Len() != 1 || got.First().String() != "Alpha" {
		t.Fatalf("expected merged name to deduplicate, got %v", got.StringSlice())
	}
	if got, found := merged.Get(DisplayName); !found || got.Len() != 1 || got.First().String() != "Display" {
		t.Fatalf("expected display name to merge, got %v", got.StringSlice())
	}
	if got, found := merged.Get(dropAttr); !found || got.Len() != 1 || got.First().String() != "left-only" {
		t.Fatalf("expected drop-when-merging attr to keep left value only, got %v", got.StringSlice())
	}
}

func TestAttributesAndValuesSetClearAndOverlapProtection(t *testing.T) {
	var values AttributesAndValues
	values.init()
	values.Set(Name, AttributeValues{NV("Alpha"), NV("Beta")})
	values.Set(DisplayName, AttributeValues{NV("Display")})
	values.Clear(DisplayName)

	if _, found := values.Get(DisplayName); found {
		t.Fatal("expected cleared attribute to be removed")
	}

	overlapping := values.values[:1]
	requirePanic(t, func() {
		values.Set(Description, overlapping)
	})
}
