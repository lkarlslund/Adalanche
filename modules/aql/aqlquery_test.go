package aql

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/query"
)

func aqlFilterByName(name string) NodeQuery {
	return NodeQuery{
		Selector: query.FilterOneAttribute{
			Attribute: engine.Name,
			FilterAttribute: query.HasStringMatch{
				Value: engine.NV(name),
			},
		},
		Reference: name,
	}
}

func TestAQLResolveSingleSourceAddsReference(t *testing.T) {
	alpha := engine.NewNode(engine.Name, "alpha")
	ao := engine.NewIndexedGraph()
	enginetest.Add(ao, alpha)

	resolver := AQLquery{
		datasource: ao,
		Sources: []NodeQuery{
			{
				Selector:  aqlFilterByName("alpha").Selector,
				Reference: "source",
			},
		},
	}

	result, err := resolver.Resolve(NewResolverOptions())
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if result.Order() != 1 || !result.HasNode(alpha) {
		t.Fatal("expected single source node in result graph")
	}
	if got := result.GetNodeData(alpha, "reference"); got != "source" {
		t.Fatalf("expected reference metadata, got %v", got)
	}
}
