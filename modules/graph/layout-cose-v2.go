package graph

import (
	"math"
	"math/rand/v2"
	"runtime"
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
)

type forceGridWork struct {
	grid         [][]int
	nodes        []layoutNode
	gridX, gridY int
	gridSize     int
}

type forceGridResult struct {
	forces       []placement
	gridX, gridY int
}

type placement struct {
	x, y float64
}

// Optimized COSE layout with spatial data structures
func (pg Graph[NodeType, EdgeType]) COSELayoutV2(settings COSELayoutOptions) map[NodeType][2]float64 {
	ui.Debug().Msgf("Starting optimized COSE v2 layout with %d nodes", len(pg.nodes))
	pg.autoCleanupEdges()

	var graphs []Graph[NodeType, EdgeType]
	graphs = append(graphs, pg)

	lastGraph := pg
	lastGraphLen := pg.Order()
	ui.Debug().Msgf("Initial graph has %d nodes", lastGraphLen)

	if settings.UseMultiLevel {
		ui.Debug().Msg("Starting multi-level coarsening")
		for lastGraphLen > 100 {
			coarsenedGraph := lastGraph.CoarsenOuterNodes()
			if coarsenedGraph.Order() == lastGraphLen {
				// Try coarsening by SCCs
				coarsenedGraph = lastGraph.CoarsenBySCCs()

				if coarsenedGraph.Order() == lastGraphLen {
					ui.Debug().Msgf("No further coarsening possible at %d nodes", lastGraphLen)
					break // No further coarsening possible
				} else {
					ui.Debug().Msgf("Coarsened graph to %d nodes by SCC", coarsenedGraph.Order())
				}
			} else {
				ui.Debug().Msgf("Coarsened graph to %d nodes by pruning outer nodes", coarsenedGraph.Order())
			}
			graphs = append(graphs, coarsenedGraph)
			lastGraphLen = coarsenedGraph.Order()
			lastGraph = coarsenedGraph
		}
	}

	// Initialize layout currentNodes
	currentNodes := make([]layoutNode, 0, len(pg.nodes))
	currentNodeMap := make(map[NodeType]*layoutNode)

	totalNodeCount := len(pg.nodes)
	totalEdgeCount := len(pg.edges)

	// Estimate area based on node count and edge density
	avgDegree := 0.0
	if totalNodeCount > 0 {
		avgDegree = float64(totalEdgeCount) / float64(totalNodeCount)
	}

	k := settings.K // overall scale

	// Area proportional to node count and average degree
	radius := math.Sqrt(float64(totalNodeCount)) * avgDegree * k
	area := radius * radius * math.Pi

	idealLineLength := settings.IdealEdgeLength * k

	initialTemp := settings.Temperature * k
	ui.Debug().Msgf("Initial layout area: %f, radius: %f, nodes: %v", area, radius, totalNodeCount)
	ui.Debug().Msgf("Calculated k: %f, initial temperature %f", k, initialTemp)

	// Random placement with better distribution
	var currentGraph Graph[NodeType, EdgeType]

	// Calculate forces in parallel
	numWorkers := runtime.GOMAXPROCS(0)

	workChan := make(chan forceGridWork, numWorkers)
	resultChan := make(chan forceGridResult, numWorkers)

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for range numWorkers {
		go func() {
			defer wg.Done()
			for workItem := range workChan {
				myGridIndex := workItem.gridY*workItem.gridSize + workItem.gridX
				myGrid := workItem.grid[myGridIndex]

				forces := make([]placement, len(myGrid))

				// Check neighboring cells in grid
				for i, nodeIdx := range myGrid {

					thisNode := workItem.nodes[nodeIdx]

					// Repulsion from other nodes
					for dy := workItem.gridY - 1; dy <= workItem.gridY+1; dy++ {
						for dx := workItem.gridX - 1; dx <= workItem.gridX+1; dx++ {
							thisGridIdx := dy*workItem.gridSize + dx
							if thisGridIdx < 0 || thisGridIdx >= len(workItem.grid) {
								continue
							}
							for _, otherNodeIdx := range workItem.grid[thisGridIdx] {
								if nodeIdx == otherNodeIdx {
									continue
								}
								otherNode := workItem.nodes[otherNodeIdx]

								dx := thisNode.x - otherNode.x
								dy := thisNode.y - otherNode.y
								distSq := dx*dx + dy*dy
								dist := math.Max(math.Sqrt(distSq), 0.01)

								// Use inverse square law for repulsion
								force := settings.RepulsionCoeff * float64(k) * float64(k) / distSq

								// Normalize and apply force
								forces[i].x += (dx / dist) * force
								forces[i].y += (dy / dist) * force
							}
						}
					}

					// Apply gravity to center using linear attraction
					dx := -thisNode.x
					dy := -thisNode.y
					dist := math.Max(math.Sqrt(dx*dx+dy*dy), 0.01)

					force := settings.Gravity * dist / k
					forces[i].x += (dx / dist) * force
					forces[i].y += (dy / dist) * force
				}

				resultChan <- forceGridResult{
					gridX:  workItem.gridX,
					gridY:  workItem.gridY,
					forces: forces,
				}
			}
		}()
	}

	// Start layout on the coarsest graph
	var totalIterations int
	var totalRounds int
	for len(graphs) > 0 {
		currentTemp := initialTemp

		ui.Debug().Msgf("Starting round %v with temperature %f", totalRounds, currentTemp)

		currentGraph = graphs[len(graphs)-1]
		graphs = graphs[:len(graphs)-1]

		// Use spatial grid for repulsion forces (O(n) instead of O(n²))
		gridSize := min(int(math.Sqrt(float64(currentGraph.Order())))/5+1, 25)
		grid := make([][]int, gridSize*gridSize)
		for i := range grid {
			grid[i] = make([]int, 0)
		}

		// apply dampening to nodes already placed
		for _, layout := range currentNodeMap {
			layout.dampeningFactor = layout.dampeningFactor * 0.5
		}

		// place missing nodes by averaging neighbors
		fwd := currentGraph.AdjacencyMap()
		rwd := currentGraph.PredecessorMap()
		for node := range currentGraph.nodes {
			if _, exists := currentNodeMap[node]; !exists {
				// Average position of neighbors
				var sumX, sumY float64
				var count float64

				for _, neighbor := range append(fwd[node], rwd[node]...) {
					if nln, ok := currentNodeMap[neighbor]; ok {
						sumX += nln.x
						sumY += nln.y
						count++
					}
				}

				var newX, newY float64
				if count == 1 {
					// Place new node slightly offset from single neighbor
					newX = sumX + (rand.Float64()-0.5)*idealLineLength
					newY = sumY + (rand.Float64()-0.5)*idealLineLength
					ui.Trace().Msgf("Placing new node %v at %f, %f with single neighbor", node, newX, newY)
				} else if count > 0 {
					// Place new node at average position of neighbors
					newX = sumX / count
					newY = sumY / count
					ui.Trace().Msgf("Placing new node %v at %f, %f with %v neighbours", node, newX, newY, count)
				} else {
					// Random placement if no neighbors are placed
					ui.Trace().Msgf("Placing new node %v randomly", node)
					angle := rand.Float64() * 2 * math.Pi
					r := radius * math.Sqrt(rand.Float64())
					newX = math.Cos(angle) * r
					newY = math.Sin(angle) * r
				}

				ln := layoutNode{
					id:              len(currentNodes),
					x:               newX,
					y:               newY,
					dampeningFactor: 1,
				}
				currentNodes = append(currentNodes, ln)
				currentNodeMap[node] = &currentNodes[len(currentNodes)-1]
			}
		}

		ui.Debug().Msgf("Refining layout on coarse graph %v with %d nodes", len(graphs), currentGraph.Order())
		stableCount := 0

		// Precompute edge list for better cache locality
		edgesSlice := make([]struct{ src, dst int }, len(currentGraph.edges))
		i := 0
		for edge, _ := range currentGraph.edges {
			edgesSlice[i] = struct{ src, dst int }{
				src: currentNodeMap[edge.Source].id,
				dst: currentNodeMap[edge.Target].id,
			}
			i++
		}

		// Main layout loop
		var iteration int
		for iteration = 0; iteration < settings.MaxIterations; iteration++ {
			// Reset grid
			for i := range grid {
				grid[i] = grid[i][:0]
			}

			// Populate grid with nodes
			for i, node := range currentNodes {
				gridIdx := int((node.x+radius)/(2*radius)*float64(gridSize)) +
					int((node.y+radius)/(2*radius)*float64(gridSize))*gridSize
				if gridIdx < 0 {
					gridIdx = 0
				} else if gridIdx >= len(grid) {
					gridIdx = len(grid) - 1
				}
				grid[gridIdx] = append(grid[gridIdx], i)
			}

			go func() {
				// Dispatch work to workers
				for gy := 0; gy < gridSize; gy++ {
					for gx := 0; gx < gridSize; gx++ {
						workChan <- forceGridWork{
							gridX:    gx,
							gridY:    gy,
							gridSize: gridSize,
							grid:     grid,
							nodes:    currentNodes,
						}
					}
				}
			}()

			// Collect forces
			for range grid {
				resultItem := <-resultChan
				gridItem := grid[resultItem.gridY*gridSize+resultItem.gridX]
				for j, result := range resultItem.forces {
					currentNodes[gridItem[j]].dx += result.x
					currentNodes[gridItem[j]].dy += result.y
				}
			}

			// Apply spring forces on edges
			for _, edge := range edgesSlice {
				source := &currentNodes[edge.src]
				target := &currentNodes[edge.dst]

				dx := source.x - target.x
				dy := source.y - target.y
				dist := math.Max(math.Sqrt(dx*dx+dy*dy), 0.01)

				// Spring force increases linearly with distance
				force := settings.SpringCoeff * (dist - idealLineLength) / k

				// Apply force with distance limiting
				dx *= force / dist
				dy *= force / dist

				source.dx -= dx
				source.dy -= dy
				target.dx += dx
				target.dy += dy
			}

			// Update positions with movement tracking
			totalMovement := 0.0
			for j := range currentNodes {
				dist := math.Sqrt(currentNodes[j].dx*currentNodes[j].dx + currentNodes[j].dy*currentNodes[j].dy)
				if dist > 0 {
					limitedDist := math.Min(dist, currentTemp*k)
					currentNodes[j].x += currentNodes[j].dx / dist * limitedDist * currentNodes[j].dampeningFactor
					currentNodes[j].y += currentNodes[j].dy / dist * limitedDist * currentNodes[j].dampeningFactor
					totalMovement += limitedDist
				}
				// Clear forces
				currentNodes[j].dx = 0
				currentNodes[j].dy = 0
			}

			// Check for stability
			avgMovement := totalMovement / float64(len(currentNodes))
			if iteration >= settings.MinIterations && avgMovement < settings.MovementThreshold*k {
				stableCount++
				if stableCount > 3 { // Require 3 consecutive stable iterations
					ui.Debug().Msgf("Layout converged after %d iterations with %f average movement", iteration, avgMovement)
					break
				}
			} else {
				stableCount = 0
			}

			// Cool temperature with better minimum
			currentTemp = math.Max(currentTemp*settings.CoolingFactor, initialTemp*0.01)
			if totalIterations%25 == 0 {
				ui.Trace().Msgf("Iteration %d - Temperature: %f - Average movement: %f", iteration, currentTemp, avgMovement)
			}
			totalIterations++
		}
		totalRounds++
	}
	close(workChan)
	close(resultChan)
	wg.Wait()

	// Convert result to coordinate map
	result := make(map[NodeType][2]float64)
	for node, layout := range currentNodeMap {
		result[node] = [2]float64{layout.x, layout.y}
	}

	ui.Debug().Msgf("COSE layout completed with %d nodes after %v rounds totalling %v iterations", len(result), totalRounds, totalIterations)
	return result
}
