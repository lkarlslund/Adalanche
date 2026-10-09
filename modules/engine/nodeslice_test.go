package engine

import "testing"

func TestNodeSliceSortSkipAndLimit(t *testing.T) {
	alpha := testNode(Name, "alpha", DisplayName, "c")
	beta := testNode(Name, "beta", DisplayName, "a")
	gamma := testNode(Name, "gamma", DisplayName, "b")
	slice := NewNodeSlice(0)
	slice.Add(alpha)
	slice.Add(beta)
	slice.Add(gamma)

	slice.Sort(DisplayName, false)
	if slice.First() != beta {
		t.Fatal("expected ascending sort by display name")
	}

	slice.Skip(1)
	if slice.Len() != 2 || slice.First() != gamma {
		t.Fatal("expected skip to drop first sorted item")
	}

	slice.Limit(1)
	if slice.Len() != 1 || slice.First() != gamma {
		t.Fatal("expected limit to trim slice")
	}
}
