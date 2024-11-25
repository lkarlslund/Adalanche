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
	MaxDepth                  int                `json:"max_depth,omitempty"`
	MaxOutgoingConnections    int                `json:"max_outgoing_connections,omitempty"`
	MinEdgeProbability        engine.Probability `json:"min_edge_probability,omitempty"`
	MinAccumulatedProbability engine.Probability `json:"min_accumulated_probability,omitempty"`
	PruneIslands              bool               `json:"prune_islands,omitempty"`
	NodeLimit                 int                `json:"nodelimit,omitempty"`
}

func ResolveWithOptions(resolver AQLresolver, opts ResolverOptions) (*graph.Graph[*engine.Object, engine.EdgeBitmap], error) {

	return nil, nil
}
