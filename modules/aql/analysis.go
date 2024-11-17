package aql

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
)

func NewResolverOptions() ResolverOptions {
	return ResolverOptions{
		MaxDepth:                  -1,
		MaxOutgoingConnections:    -1,
		MinEdgeProbability:        0,
		MinAccumulatedProbability: 0,
		PruneIslands:              false,
	}
}

type ResolverOptions struct {
	MaxDepth                  int
	MaxOutgoingConnections    int
	MinEdgeProbability        engine.Probability
	MinAccumulatedProbability engine.Probability
	PruneIslands              bool
	NodeLimit                 int
}

func ResolveWithOptions(resolver AQLresolver, opts ResolverOptions) (*graph.Graph[*engine.Object, engine.EdgeBitmap], error) {

	return nil, nil
}
