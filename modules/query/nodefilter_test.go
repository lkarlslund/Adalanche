package query

import (
	"testing"

	"github.com/gobwas/glob"
	"github.com/lkarlslund/adalanche/modules/engine"
)

func TestComparatorCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		comp Comparator[int]
		a    int
		b    int
		want bool
	}{
		{name: "equal", comp: Comparator[int](CompareEqual), a: 4, b: 4, want: true},
		{name: "different", comp: Comparator[int](CompareDifferent), a: 4, b: 5, want: true},
		{name: "less-than", comp: Comparator[int](CompareLessThan), a: 4, b: 5, want: true},
		{name: "lte", comp: Comparator[int](CompareLessThanEqual), a: 4, b: 4, want: true},
		{name: "greater-than", comp: Comparator[int](CompareGreaterThan), a: 6, b: 5, want: true},
		{name: "gte", comp: Comparator[int](CompareGreaterThanEqual), a: 6, b: 6, want: true},
		{name: "invalid", comp: Comparator[int](CompareInvalid), a: 1, b: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.comp.Compare(tt.a, tt.b); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestAttributeComparisonEvaluate(t *testing.T) {
	t.Parallel()

	node := engine.NewNode(engine.Name, "Alpha")
	comparison := AttributeComparison{
		Value:      engine.NV("alpha"),
		Comparator: CompareEqual,
	}

	if !comparison.Evaluate(engine.Name, node) {
		t.Fatal("expected case-insensitive equality match")
	}
}

func TestAttributeComparisonPanicsOnUnknownComparator(t *testing.T) {
	t.Parallel()

	node := engine.NewNode(engine.Name, "Alpha")
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic from unknown comparator")
		}
	}()
	AttributeComparison{
		Value:      engine.NV("alpha"),
		Comparator: ComparatorType(99),
	}.Evaluate(engine.Name, node)
}

func TestCountModifierAndGlobMatch(t *testing.T) {
	t.Parallel()

	node := engine.NewNode(engine.Name, "Alpha", engine.Description, []string{"one", "two"})

	if !(CountModifier{Comparator: CompareEqual, Value: 2}).Evaluate(engine.Description, node) {
		t.Fatal("expected count modifier to match two values")
	}
	if !(HasGlobMatch{Match: glob.MustCompile("alp*"), Globstr: "alp*"}).Evaluate(engine.Name, node) {
		t.Fatal("expected glob modifier to match")
	}
}
