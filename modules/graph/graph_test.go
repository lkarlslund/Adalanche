package graph_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/lkarlslund/adalanche/modules/graph"
)

type TestNode int

type TestPair struct {
	from, to int
}

type TestEdge struct{}

// Dummy function to satisfy interface
func (de TestEdge) Merge(de2 TestEdge) TestEdge {
	return de
}

func sortSCC(sccs [][]int) {
	for _, scc := range sccs {
		slices.Sort(scc)
	}
	slices.SortFunc(sccs, func(a, b []int) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		for i := range a {
			if a[i] != b[i] {
				return a[i] - b[i]
			}
		}
		return 0
	})
}

var tests = []struct {
	name  string // description of this test case
	edges []TestPair
	want  [][]int
}{
	{
		// TODO: Add test cases.
		name: "Gabow simple",
		edges: []TestPair{
			{1, 2},
			{2, 3},
			{3, 1},
			{3, 4},
			{4, 5},
			{5, 4},
		},
		want: [][]int{
			{1, 2, 3},
			{4, 5},
		},
	},
	{
		name: "Gabow single nodes",
		edges: []TestPair{
			{1, 2},
			{2, 3},
			{4, 5},
		},
		want: [][]int{
			{1},
			{2},
			{3},
			{4},
			{5},
		},
	},
	{
		name: "Gabow complex",
		edges: []TestPair{
			{1, 2},
			{2, 3},
			{3, 1},
			{3, 4},
			{4, 5},
			{5, 6},
			{6, 4},
			{7, 6},
			{7, 8},
			{8, 7},
			{8, 9},
			{9, 10},
			{10, 11},
			{11, 9},
			{12, 11},
		},
		want: [][]int{
			{1, 2, 3},
			{4, 5, 6},
			{7, 8},
			{9, 10, 11},
			{12},
		},
	},
}

func TestGraph_SCCGabow(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			g := graph.NewGraph[int, TestEdge]()
			for _, e := range tt.edges {
				g.AddEdge(e.from, e.to, TestEdge{})
			}
			got := g.SCCGabow()

			sortSCC(got)
			sortSCC(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SCCGabow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGraph_SCCTarjan(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			g := graph.NewGraph[int, TestEdge]()
			for _, e := range tt.edges {
				g.AddEdge(e.from, e.to, TestEdge{})
			}
			got := g.SCCTarjan()

			sortSCC(got)
			sortSCC(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SCCTarjan() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGraph_SCCKosaraju(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			g := graph.NewGraph[int, TestEdge]()
			for _, e := range tt.edges {
				g.AddEdge(e.from, e.to, TestEdge{})
			}
			got := g.SCCKosaraju()

			sortSCC(got)
			sortSCC(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SCCKosaraju() = %v, want %v", got, tt.want)
			}
		})
	}
}
