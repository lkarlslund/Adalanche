package aql

import (
	"context"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
)

// DefaultNodeLimit bounds a query's result when the caller sets no limit, so a
// broad query on any endpoint cannot grow without bound. Callers that want more
// raise NodeLimit; -1 removes the per-request limit (still capped by the hard
// ceiling in the resolvers).
const DefaultNodeLimit = 100000

// Hard ceilings the resolvers enforce no matter what options a caller passes
// (including NodeLimit -1), so no query can exhaust memory and take the server
// down. They are generous enough not to truncate normal results.
const (
	// HardNodeCeiling caps a query's result in nodes.
	HardNodeCeiling = 2000000
	// MaxPathSearchStates caps how many partial paths the enumerating modes
	// (ACYCLIC, TRAIL, WALK) explore; path enumeration is exponential, so the
	// search frontier, not the result, is what runs away.
	MaxPathSearchStates = 20000000
)

// effectiveNodeLimit is the node limit to enforce: the caller's, or the hard
// ceiling when they asked for none or for more than is safe.
func effectiveNodeLimit(nodeLimit int) int {
	if nodeLimit <= 0 || nodeLimit > HardNodeCeiling {
		return HardNodeCeiling
	}
	return nodeLimit
}

func NewResolverOptions() ResolverOptions {
	return ResolverOptions{
		MaxDepth:                  -1,
		MaxOutgoingConnections:    -1,
		NodeLimit:                 DefaultNodeLimit,
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
