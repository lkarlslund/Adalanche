package aql

import (
	"context"

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
	NodeLimit                 int                `json:"nodelimit,omitempty"`
	MinEdgeProbability        engine.Probability `json:"min_edge_probability,omitempty"`
	MinAccumulatedProbability engine.Probability `json:"min_accumulated_probability,omitempty"`
	PruneIslands              bool               `json:"prune_islands,omitempty"`
	// MergeNodes draws nodes as one as the mode says (see MergeMode), and
	// counts nodes as drawn against the node limit where the query mode
	// allows.
	MergeNodes MergeMode `json:"merge_nodes,omitempty"`
	// Context stops the search when it is done, such as when the client
	// that asked has gone. Nil never stops it.
	Context context.Context `json:"-"`
}

// cancelled returns why the search should stop, or nil to go on.
func (o ResolverOptions) cancelled() error {
	if o.Context == nil {
		return nil
	}
	return o.Context.Err()
}

func ResolveWithOptions(resolver AQLresolver, opts ResolverOptions) (*graph.Graph[*engine.Node, engine.EdgeBitmap], error) {
	return nil, nil
}
