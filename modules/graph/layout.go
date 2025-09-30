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
	Gravity           float64 // Gravity force strength
	IdealEdgeLength   float64 // Ideal edge length
	SpringCoeff       float64 // Spring coefficient
	RepulsionCoeff    float64 // Repulsion coefficient
	MaxIterations     int     // Maximum iterations
	Temperature       float64 // Initial temperature
	CoolingFactor     float64 // Temperature cooling factor
	MinTemperature    float64 // Minimum temperature for early termination
	UseMultiLevel     bool    // Use multi-level scaling
	MovementThreshold float64 // Movement threshold for early termination
	MinIterations     int     // Minimum iterations before early termination
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
		Gravity:           0.05, // Reduced gravity
		IdealEdgeLength:   50,   // Base distance
		SpringCoeff:       0.8,  // Spring force
		RepulsionCoeff:    1.2,  // Slightly stronger repulsion
		MaxIterations:     1000,
		Temperature:       1.0,  // Start with lower temperature
		CoolingFactor:     0.98, // Slower cooling
		UseMultiLevel:     true,
		MovementThreshold: 0.1, // More strict convergence
		MinIterations:     50,
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

func calculateForces[NodeType GraphNodeInterface[NodeType]](work forceWork[NodeType]) forceResult[NodeType] {
	forces := make([][2]float64, work.endIdx-work.startIdx)

	// Calculate forces for our chunk
	for localIdx := 0; localIdx < work.endIdx-work.startIdx; localIdx++ {
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

	return forceResult[NodeType]{
		startIdx: work.startIdx,
		endIdx:   work.endIdx,
		forces:   forces,
	}
}

func forceWorker[NodeType GraphNodeInterface[NodeType]](
	jobs <-chan forceWork[NodeType],
	results chan<- forceResult[NodeType],
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for work := range jobs {
		results <- calculateForces(work)
	}
}

// COSELayout computes COSE layout coordinates for the graph
func (pg *Graph[NodeType, EdgeType]) COSELayout(settings COSELayoutOptions) map[NodeType][2]float64 {
	pg.autoCleanupEdges()

	// Initialize layout nodes
	nodes := make([]layoutNode[NodeType], 0, len(pg.nodes))
	nodeMap := make(map[NodeType]*layoutNode[NodeType])

	// Better initial positions
	idx := 0
	area := float64(len(pg.nodes)) * settings.IdealEdgeLength * settings.IdealEdgeLength
	radius := math.Sqrt(area) / 2
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

	// Better space scaling
	k := math.Sqrt(area / float64(len(nodes)))
	temp := settings.Temperature * k

	stableCount := 0

	// Set up parallel force calculation
	numWorkers := runtime.GOMAXPROCS(0)
	jobs := make(chan forceWork[NodeType], 16)
	results := make(chan forceResult[NodeType], 16)
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	// Start workers
	for w := 0; w < numWorkers; w++ {
		go forceWorker(jobs, results, &wg)
	}

	// Main layout loop
	for iteration := 0; iteration < settings.MaxIterations; iteration++ {
		// Distribute work
		workSize := (len(nodes) + 15) / 16
		jobCount := (len(nodes) + workSize - 1) / workSize

		// Queue jobs in the background
		go func() {
			for job := 0; job < jobCount; job++ {
				start := job * workSize
				end := start + workSize
				if job == jobCount-1 {
					end = len(nodes)
				}
				jobs <- forceWork[NodeType]{
					startIdx: start,
					endIdx:   end,
					nodes:    nodes,
					k:        k,
					settings: settings,
				}
			}
		}()

		// Apply force results to nodes
		for i := 0; i < jobCount; i++ {
			result := <-results
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
			force := settings.SpringCoeff * (dist - settings.IdealEdgeLength) / k

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
					limitedDist := math.Min(dist, temp*k)
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
		if iteration >= settings.MinIterations && avgMovement < settings.MovementThreshold {
			stableCount++
			if stableCount > 3 { // Require 3 consecutive stable iterations
				break
			}
		} else {
			stableCount = 0
		}

		// Cool temperature with better minimum
		temp = math.Max(temp*settings.CoolingFactor, k*0.01)
	}

	// Proper cleanup of worker goroutines
	close(jobs)
	wg.Wait()
	close(results)

	if len(results) != 0 {
		ui.Error().Msgf("Unexpected remaining results: %d", len(results))
	}

	// Convert result to coordinate map
	result := make(map[NodeType][2]float64)
	for _, node := range nodes {
		result[node.node] = [2]float64{node.x, node.y}
	}

	return result
}
