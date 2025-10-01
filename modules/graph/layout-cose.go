package graph

import (
	"math"
	"math/rand/v2"
	"runtime"
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
)

type COSELayoutOptions struct {
	// Layout parameters
	Gravity           float64 `json:"gravity,omitempty"`            // Gravity force strength
	IdealEdgeLength   float64 `json:"ideal_edge_length,omitempty"`  // Ideal edge length
	SpringCoeff       float64 `json:"spring_coeff,omitempty"`       // Spring coefficient
	RepulsionCoeff    float64 `json:"repulsion_coeff,omitempty"`    // Repulsion coefficient
	MaxIterations     int     `json:"max_iterations,omitempty"`     // Maximum iterations
	Temperature       float64 `json:"temperature,omitempty"`        // Initial temperature
	CoolingFactor     float64 `json:"cooling_factor,omitempty"`     // Temperature cooling factor
	MinTemperature    float64 `json:"min_temperature,omitempty"`    // Minimum temperature for early termination
	UseMultiLevel     bool    `json:"use_multi_level,omitempty"`    // Use multi-level scaling
	MovementThreshold float64 `json:"movement_threshold,omitempty"` // Movement threshold for early termination
	MinIterations     int     `json:"min_iterations,omitempty"`     // Minimum iterations before early termination
}

type layoutNode[NodeType GraphNodeInterface[NodeType]] struct {
	id     int // Add index for proper force mapping
	node   NodeType
	x, y   float64
	dx, dy float64
	fixed  bool
}

func DefaultLayoutSettings() COSELayoutOptions {
	return COSELayoutOptions{
		MinIterations:     50,    // Ensure some minimum iterations
		MaxIterations:     2500,  // No more than these iterations
		MovementThreshold: 0.002, // More strict convergence

		Gravity:        0.05, // Gravity that pulls nodes to center
		SpringCoeff:    0.8,  // Spring force for the ideal edge length
		RepulsionCoeff: 1.3,  // Repulsion between nodes

		IdealEdgeLength: 2,    // Base distance
		Temperature:     1.0,  // Start with lower temperature
		CoolingFactor:   0.98, // Slower cooling
		UseMultiLevel:   true,
	}
}

// Work item for force calculation
type forceWork[NodeType GraphNodeInterface[NodeType]] struct {
	startIdx, endIdx int
	nodes            []layoutNode[NodeType]
	k                float64
	settings         COSELayoutOptions
}

type forceResult[NodeType GraphNodeInterface[NodeType]] struct {
	startIdx, endIdx int
	forces           [][2]float64
}

// COSELayout computes COSE layout coordinates for the graph
func (pg *Graph[NodeType, EdgeType]) COSELayout(settings COSELayoutOptions) map[NodeType][2]float64 {
	ui.Debug().Msgf("Starting COSE layout with %d nodes", len(pg.nodes))
	pg.autoCleanupEdges()

	// Initialize layout nodes
	nodes := make([]layoutNode[NodeType], 0, len(pg.nodes))
	nodeMap := make(map[NodeType]*layoutNode[NodeType])

	nodeCount := len(pg.nodes)
	edgeCount := len(pg.edges)

	// Better initial positions
	idx := 0

	// Estimate area based on node count and edge density
	// This helps prevent overly tight or loose layouts
	avgDegree := 0.0
	if nodeCount > 0 {
		avgDegree = float64(edgeCount) / float64(nodeCount)
	}

	// Area proportional to node count and average degree
	area := float64(nodeCount) * (float64(nodeCount) + avgDegree) * 50

	radius := math.Sqrt(area) / 2
	k := radius / 4

	// Ensure k is not too small
	if k < 1.0 {
		k = 1.0
	}

	idealLineLength := settings.IdealEdgeLength * k / 8

	currentTemp := settings.Temperature * k
	ui.Debug().Msgf("Initial layout area: %f, radius: %f, nodes: %f", area, radius, nodeCount)
	ui.Debug().Msgf("Calculated k: %f, temperature %f", k, currentTemp)
	for node := range pg.nodes {
		angle := rand.Float64() * 2 * math.Pi
		r := radius * math.Sqrt(rand.Float64()) // Better radial distribution
		ln := layoutNode[NodeType]{
			id:   idx,
			node: node,
			x:    math.Cos(angle) * r,
			y:    math.Sin(angle) * r,
		}
		nodes = append(nodes, ln)
		nodeMap[node] = &nodes[idx]
		idx++
	}

	stableCount := 0

	// Set up parallel force calculation
	numWorkers := runtime.GOMAXPROCS(0)
	itemsPerTask := len(nodes) / numWorkers / 16
	if itemsPerTask < 16 {
		itemsPerTask = 16
	}
	taskCount := (nodeCount + itemsPerTask - 1) / itemsPerTask

	jobChan := make(chan forceWork[NodeType], 16)
	resultChan := make(chan forceResult[NodeType], 16)

	// Start workers
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for range numWorkers {
		go func() {
			defer wg.Done()
			forces := make([][2]float64, itemsPerTask)
			for work := range jobChan {
				// Calculate forces for our chunk
				for localIdx := 0; localIdx < work.endIdx-work.startIdx; localIdx++ {
					forces[localIdx][0] = 0 // Reset forces
					forces[localIdx][1] = 0

					j := localIdx + work.startIdx

					// Apply repulsion forces against all nodes
					for k := range work.nodes {
						if j != k {
							dx := work.nodes[j].x - work.nodes[k].x
							dy := work.nodes[j].y - work.nodes[k].y
							distSq := dx*dx + dy*dy
							dist := math.Max(math.Sqrt(distSq), 0.01)

							// Use inverse square law for repulsion
							force := work.settings.RepulsionCoeff * work.k * work.k / distSq

							// Normalize and apply force
							forces[localIdx][0] += (dx / dist) * force
							forces[localIdx][1] += (dy / dist) * force
						}
					}

					// Apply gravity to center using linear attraction
					dx := -work.nodes[j].x
					dy := -work.nodes[j].y
					dist := math.Max(math.Sqrt(dx*dx+dy*dy), 0.01)

					force := work.settings.Gravity * dist / work.k
					forces[localIdx][0] += (dx / dist) * force
					forces[localIdx][1] += (dy / dist) * force
				}

				resultChan <- forceResult[NodeType]{
					startIdx: work.startIdx,
					endIdx:   work.endIdx,
					forces:   forces[:work.endIdx-work.startIdx],
				}
			}
		}()
	}

	// Main layout loop
	for iteration := 0; iteration < settings.MaxIterations; iteration++ {
		// Queue jobs in the background
		go func() {
			for job := 0; job < taskCount; job++ {
				start := job * itemsPerTask
				end := start + itemsPerTask
				if job == taskCount-1 {
					end = nodeCount
				}
				jobChan <- forceWork[NodeType]{
					startIdx: start,
					endIdx:   end,
					nodes:    nodes,
					k:        k,
					settings: settings,
				}
			}
		}()

		// Apply force results to nodes
		for i := 0; i < taskCount; i++ {
			result := <-resultChan
			for localIdx := 0; localIdx < result.endIdx-result.startIdx; localIdx++ {
				nodeIdx := localIdx + result.startIdx
				nodes[nodeIdx].dx += result.forces[localIdx][0]
				nodes[nodeIdx].dy += result.forces[localIdx][1]
			}
		}

		// Apply spring forces on edges
		for pair := range pg.edges {
			source := nodeMap[pair.Source]
			target := nodeMap[pair.Target]

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
		for j := range nodes {
			if !nodes[j].fixed {
				dist := math.Sqrt(nodes[j].dx*nodes[j].dx + nodes[j].dy*nodes[j].dy)
				if dist > 0 {
					limitedDist := math.Min(dist, currentTemp*k)
					nodes[j].x += nodes[j].dx / dist * limitedDist
					nodes[j].y += nodes[j].dy / dist * limitedDist
					totalMovement += limitedDist
				}
			}
			// Clear forces
			nodes[j].dx = 0
			nodes[j].dy = 0
		}

		// Check for stability
		avgMovement := totalMovement / float64(len(nodes))
		ui.Trace().Msgf("Iteration %d - Average movement: %f", iteration, avgMovement)
		if iteration >= settings.MinIterations && avgMovement < settings.MovementThreshold*k {
			stableCount++
			if stableCount > 3 { // Require 3 consecutive stable iterations
				ui.Debug().Msgf("Layout converged after %d iterations", iteration)
				break
			}
		} else {
			stableCount = 0
		}

		// Cool temperature with better minimum
		currentTemp = math.Max(currentTemp*settings.CoolingFactor, k*0.01)
		ui.Trace().Msgf("Iteration %d - Temperature: %f", iteration, currentTemp)
	}

	// Proper cleanup of worker goroutines
	close(jobChan)
	wg.Wait()
	close(resultChan)

	if len(resultChan) != 0 {
		ui.Error().Msgf("Unexpected remaining results: %d", len(resultChan))
	}

	// Convert result to coordinate map
	result := make(map[NodeType][2]float64)
	for _, node := range nodes {
		result[node.node] = [2]float64{node.x, node.y}
	}

	ui.Debug().Msgf("COSE layout completed with %d nodes", len(result))
	return result
}
