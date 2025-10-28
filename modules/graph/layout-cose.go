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
	NodeDistance      float64 `json:"node_distance,omitempty"`      // Minimum distance between nodes
	MaxIterations     int     `json:"max_iterations,omitempty"`     // Maximum iterations
	Temperature       float64 `json:"temperature,omitempty"`        // Initial temperature
	CoolingFactor     float64 `json:"cooling_factor,omitempty"`     // Temperature cooling factor
	MinTemperature    float64 `json:"min_temperature,omitempty"`    // Minimum temperature for early termination
	UseMultiLevel     bool    `json:"use_multi_level,omitempty"`    // Use multi-level scaling
	MovementThreshold float64 `json:"movement_threshold,omitempty"` // Movement threshold for early termination
	MinIterations     int     `json:"min_iterations,omitempty"`     // Minimum iterations before early termination
	K                 float64 `json:"k,omitempty"`                  // Scaling factor
}

func DefaultLayoutSettings() COSELayoutOptions {
	return COSELayoutOptions{
		MinIterations:     50,   // Ensure some minimum iterations
		MaxIterations:     5000, // No more than these iterations
		MovementThreshold: 0.01, // More strict convergence

		Gravity:        0.04, // Gravity that pulls nodes to center
		SpringCoeff:    0.6,  // Spring force for the ideal edge length
		RepulsionCoeff: 2,    // Repulsion between nodes
		NodeDistance:   4,    // Minimum distance between nodes

		IdealEdgeLength: 5,     // Base distance
		Temperature:     1.0,   // Start with lower temperature
		CoolingFactor:   0.995, // Slower cooling

		K: 60, // Base scaling factor

		UseMultiLevel: true,
	}
}

// Work item for force calculation
type layoutNode struct {
	id              int // Add index for proper force mapping
	x, y            float64
	dx, dy          float64
	dampeningFactor float64
}

type forceWork struct {
	startIdx, endIdx int
	nodes            []layoutNode
	k                float64
	settings         COSELayoutOptions
}

type forceResult struct {
	startIdx, endIdx int
	forces           [][2]float64
}

// COSELayout computes COSE layout coordinates for the graph
func (pg *Graph[NodeType, EdgeType]) COSELayoutV1(settings COSELayoutOptions) map[NodeType][2]float64 {
	ui.Debug().Msgf("Starting COSE layout with %d nodes", len(pg.nodes))
	pg.autoCleanupEdges()

	// Initialize layout nodes
	nodes := make([]layoutNode, 0, len(pg.nodes))
	nodeMap := make(map[NodeType]*layoutNode)

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

	k := settings.K // overall scale

	// Area proportional to node count and average degree
	radius := math.Sqrt(float64(nodeCount)) * avgDegree * k
	area := radius * radius * math.Pi

	idealLineLength := settings.IdealEdgeLength * k

	currentTemp := settings.Temperature * k
	ui.Debug().Msgf("Initial layout area: %f, radius: %f, nodes: %f", area, radius, nodeCount)
	ui.Debug().Msgf("Calculated k: %f, temperature %f", k, currentTemp)

	// random placement
	for node := range pg.nodes {
		angle := rand.Float64() * 2 * math.Pi
		r := radius * math.Sqrt(rand.Float64()) // Better radial distribution
		ln := layoutNode{
			id:              idx,
			x:               math.Cos(angle) * r,
			y:               math.Sin(angle) * r,
			dampeningFactor: 1,
		}
		nodes = append(nodes, ln)
		nodeMap[node] = &nodes[idx]
		idx++
	}

	stableCount := 0

	// Set up parallel force calculation
	numWorkers := runtime.GOMAXPROCS(0)
	itemsPerTask := max(len(nodes)/numWorkers/16, 16)
	taskCount := (nodeCount + itemsPerTask - 1) / itemsPerTask

	jobChan := make(chan forceWork, 16)
	resultChan := make(chan forceResult, 16)

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
					for workNode := range work.nodes {
						if j != workNode {
							dx := work.nodes[j].x - work.nodes[workNode].x
							dy := work.nodes[j].y - work.nodes[workNode].y
							distSq := dx*dx + dy*dy
							dist := math.Max(math.Sqrt(distSq), 0.01)

							// Enforce minimum node distance
							if dist < work.settings.NodeDistance*k {
								dist = work.settings.NodeDistance * k
								distSq = dist * dist
							}

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

				resultChan <- forceResult{
					startIdx: work.startIdx,
					endIdx:   work.endIdx,
					forces:   forces[:work.endIdx-work.startIdx],
				}
			}
		}()
	}

	// Main layout loop
	var iteration int
	for iteration = 0; iteration < settings.MaxIterations; iteration++ {
		// Queue jobs in the background
		go func() {
			for job := range taskCount {
				start := job * itemsPerTask
				end := start + itemsPerTask
				if job == taskCount-1 {
					end = nodeCount
				}
				jobChan <- forceWork{
					startIdx: start,
					endIdx:   end,
					nodes:    nodes,
					k:        k,
					settings: settings,
				}
			}
		}()

		// Apply force results to nodes
		for range taskCount {
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
			dist := math.Sqrt(nodes[j].dx*nodes[j].dx + nodes[j].dy*nodes[j].dy)
			if dist > 0 {
				limitedDist := math.Min(dist, currentTemp*k)
				nodes[j].x += nodes[j].dx / dist * limitedDist * nodes[j].dampeningFactor
				nodes[j].y += nodes[j].dy / dist * limitedDist * nodes[j].dampeningFactor
				totalMovement += limitedDist
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
	for node, layout := range nodeMap {
		result[node] = [2]float64{layout.x, layout.y}
	}

	ui.Debug().Msgf("COSE layout completed with %d nodes after %v iterations", len(result), iteration)
	return result
}
