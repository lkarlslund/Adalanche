package frontend

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/graph"
)

type GraphNode struct {
	CanExpand              int
	processRound           int
	accumulatedprobability float32 // 0-1
}

type PostProcessorFunc func(pg graph.Graph[*engine.Object, engine.EdgeBitmap]) graph.Graph[*engine.Object, engine.EdgeBitmap]

var PostProcessors []PostProcessorFunc

type AnalysisResults struct {
	Graph   graph.Graph[*engine.Object, engine.EdgeBitmap]
	Removed int
}
