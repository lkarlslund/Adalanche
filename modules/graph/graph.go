package graph

import (
	"errors"
	"maps"

	"github.com/gammazero/deque"
)

type GraphNodeInterface[NT any] interface {
	comparable
	// NodeID() NodeID
}

type GraphEdgeInterface[ET any] interface {
	Merge(ET) ET
}

type NodePair[NodeType GraphNodeInterface[NodeType]] struct {
	Source NodeType
	Target NodeType
}

type Edge[EdgeType GraphEdgeInterface[EdgeType]] struct {
	Data map[string]any
	Edge EdgeType
	Flow int
}

type Graph[NodeType GraphNodeInterface[NodeType], EdgeType GraphEdgeInterface[EdgeType]] struct {
	nodes              map[NodeType]map[string]any
	edges              map[NodePair[NodeType]]Edge[EdgeType]
	cleanupEdgesNeeded bool
}

func NewGraph[NodeType GraphNodeInterface[NodeType], EdgeType GraphEdgeInterface[EdgeType]]() Graph[NodeType, EdgeType] {
	return Graph[NodeType, EdgeType]{
		nodes: make(map[NodeType]map[string]any),
		edges: make(map[NodePair[NodeType]]Edge[EdgeType]),
	}
}

func (pg *Graph[NodeType, EdgeType]) Clone() Graph[NodeType, EdgeType] {
	newGraph := NewGraph[NodeType, EdgeType]()
	if pg != nil {
		newGraph.edges = maps.Clone(pg.edges)
		newGraph.nodes = maps.Clone(pg.nodes)
	}
	return newGraph
}

func (pg *Graph[NodeType, EdgeType]) Nodes() map[NodeType]map[string]any {
	return pg.nodes
}

func (pg *Graph[NodeType, EdgeType]) AddNode(newnode NodeType) {
	if !pg.HasNode(newnode) {
		pg.nodes[newnode] = nil
	}
}

func (pg *Graph[NodeType, EdgeType]) HasNode(find NodeType) (found bool) {
	_, found = pg.nodes[find]
	return
}

func (pg *Graph[NodeType, EdgeType]) NoAutoClean() {
	pg.cleanupEdgesNeeded = false
}

func (pg *Graph[NodeType, EdgeType]) DeleteNode(find NodeType) error {
	delete(pg.nodes, find)
	pg.cleanupEdgesNeeded = true
	return nil
}

// Sets a custom value on a node, adding it to the graph if it's not already there
func (pg *Graph[NodeType, EdgeType]) SetNodeData(node NodeType, key string, value any) error {
	fields := pg.nodes[node]
	if fields == nil {
		fields = make(map[string]any)
		pg.nodes[node] = fields
	}
	fields[key] = value
	return nil
}

func (pg *Graph[NodeType, EdgeType]) GetNodeData(node NodeType, key string) any {
	fields, found := pg.nodes[node]
	if !found {
		return nil
	}
	if fields == nil {
		return nil
	}
	return fields[key]
}

// CleanupEdges removes any edges that have no nodes
func (pg *Graph[NodeType, EdgeType]) autoCleanupEdges() {
	if !pg.cleanupEdgesNeeded {
		return
	}
	for pair, _ := range pg.edges {
		if !pg.HasNode(pair.Source) || !pg.HasNode(pair.Target) {
			delete(pg.edges, pair)
		}
	}
	pg.cleanupEdgesNeeded = false
}

func (pg *Graph[NodeType, EdgeType]) IterateEdges(ef func(NodeType, NodeType, EdgeType, int) bool) {
	for pair, edge := range pg.edges {
		if !ef(pair.Source, pair.Target, edge.Edge, edge.Flow) {
			break
		}
	}
}

// func (pg *Graph[NodeType, EdgeType]) Edges() map[NodePair[NodeType]]EdgeType {
// 	pg.autoCleanupEdges()
// 	return pg.edges
// }

// AddEdge adds an edge between two nodes, and ensures that both nodes exist
func (pg *Graph[NodeType, EdgeType]) AddEdge(source, target NodeType, edge EdgeType) {
	pg.AddNode(source)
	pg.AddNode(target)
	existing := pg.edges[NodePair[NodeType]{Source: source, Target: target}]
	existing.Edge = edge
	existing.Flow++
	pg.edges[NodePair[NodeType]{Source: source, Target: target}] = existing
}

// GetEdge returns the edge between two nodes
func (pg *Graph[NodeType, EdgeType]) GetEdge(source, target NodeType) (EdgeType, bool) {
	pg.autoCleanupEdges()
	e, found := pg.edges[NodePair[NodeType]{Source: source, Target: target}]
	return e.Edge, found
}

func (pg *Graph[NodeType, EdgeType]) HasEdge(source, target NodeType) bool {
	pg.autoCleanupEdges()
	_, found := pg.edges[NodePair[NodeType]{Source: source, Target: target}]
	return found
}

// DeleteEdge removes an edge
func (pg *Graph[NodeType, EdgeType]) DeleteEdge(source, target NodeType) {
	delete(pg.edges, NodePair[NodeType]{Source: source, Target: target})
}

// Sets a custom value on a node, adding it to the graph if it's not already there
func (pg *Graph[NodeType, EdgeType]) SetEdgeData(source, target NodeType, key string, value any) error {
	edge := pg.edges[NodePair[NodeType]{Source: source, Target: target}]
	if edge.Data == nil {
		edge.Data = make(map[string]any)
		pg.edges[NodePair[NodeType]{Source: source, Target: target}] = edge
	}
	edge.Data[key] = value
	return nil
}

func (pg *Graph[NodeType, EdgeType]) GetEdgeData(source, target NodeType, key string) any {
	edge, found := pg.edges[NodePair[NodeType]{Source: source, Target: target}]
	if !found {
		return nil
	}
	if edge.Data == nil {
		return nil
	}
	return edge.Data[key]
}

// Merge combines two graphs
func (pg *Graph[NodeType, EdgeType]) Merge(npg Graph[NodeType, EdgeType]) {
	for otherNode, otherNodeData := range npg.nodes {
		if ourNodeData, found := pg.nodes[otherNode]; !found {
			pg.nodes[otherNode] = otherNodeData
		} else {
			if ourNodeData == nil {
				pg.nodes[otherNode] = otherNodeData
			} else {
				maps.Copy(ourNodeData, otherNodeData)
			}
		}
	}

	for otherconnection, otheredge := range npg.edges {
		if ouredge, found := pg.edges[otherconnection]; found {
			mergededge := ouredge.Edge.Merge(otheredge.Edge)
			mergeddata := ouredge.Data
			if mergeddata == nil {
				mergeddata = otheredge.Data
			} else if otheredge.Data != nil {
				maps.Copy(mergeddata, otheredge.Data)
			}
			pg.edges[otherconnection] = Edge[EdgeType]{
				Edge: mergededge,
				Flow: ouredge.Flow + otheredge.Flow,
				Data: mergeddata}
		} else {
			pg.edges[otherconnection] = otheredge
		}
	}
}

// SCCKosaraju Kosaraju's Algorithm for finding strongly connected components (two DFS passes)
func (pg Graph[NodeType, EdgeType]) SCCKosaraju() [][]NodeType {
	pg.autoCleanupEdges()

	nodeToOffset := make(map[NodeType]int)
	offsetToNode := make([]NodeType, len(pg.nodes))

	var i int
	for nodeid, _ := range pg.nodes {
		nodeToOffset[nodeid] = i
		offsetToNode[i] = nodeid
		i++
	}

	neighbours := make([][]int, len(pg.nodes))
	for connection, _ := range pg.edges {
		node := nodeToOffset[connection.Source]
		neighbours[node] = append(neighbours[node], nodeToOffset[connection.Target])
	}

	// 1
	visited := make([]bool, len(pg.nodes))
	// 2

	stack := []int{}

	//3
	for node := range neighbours {
		if !visited[node] {
			dfs(neighbours, visited, &stack, node)
		}
	}
	//4
	transposed := transpose(neighbours)
	//5
	visited = make([]bool, len(pg.nodes))
	//6

	var results [][]NodeType

	for len(stack) != 0 {
		//7
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		//8
		if !visited[v] {
			sccgroup := visit(transposed, visited, v)
			// if len(sccgroup) > 1 {
			objs := make([]NodeType, len(sccgroup))
			for i, node := range sccgroup {
				objs[i] = offsetToNode[node]
			}
			// }
			results = append(results, objs)
		}
	}
	return results
}

// SCC Tarjan Algorithm Implementation (one pass)
func (g *Graph[NodeType, EdgeType]) SCCTarjan() [][]NodeType {
	successors := g.SuccessorMap() // precompute adjacency lists

	index := 0
	stack := []NodeType{}
	onStack := make(map[NodeType]bool)
	indices := make(map[NodeType]int)
	lowlink := make(map[NodeType]int)

	var result [][]NodeType

	var strongConnect func(v NodeType)
	strongConnect = func(v NodeType) {
		indices[v] = index
		lowlink[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		// iterate successors
		for _, w := range successors[v] {
			if _, ok := indices[w]; !ok {
				strongConnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}

		// SCC root
		if lowlink[v] == indices[v] {
			var scc []NodeType
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			result = append(result, scc)
		}
	}

	for v := range g.nodes {
		if _, ok := indices[v]; !ok {
			strongConnect(v)
		}
	}

	return result
}

// SCC Gabow Algorithm Implementation (one pass)
func (g *Graph[NodeType, EdgeType]) SCCGabow() [][]NodeType {
	successors := g.SuccessorMap() // precompute adjacency lists
	index := 0
	stack := []NodeType{}
	path := []NodeType{}
	indices := make(map[NodeType]int)
	onStack := make(map[NodeType]bool)
	var result [][]NodeType
	var strongConnect func(v NodeType)
	strongConnect = func(v NodeType) {
		indices[v] = index
		index++
		stack = append(stack, v)
		path = append(path, v)
		onStack[v] = true
		for _, w := range successors[v] {
			if _, ok := indices[w]; !ok {
				strongConnect(w)
			} else if onStack[w] {
				for len(path) > 0 && indices[path[len(path)-1]] > indices[w] {
					path = path[:len(path)-1]
				}
			}
		}
		if len(path) > 0 && path[len(path)-1] == v {
			var scc []NodeType
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			result = append(result, scc)
			path = path[:len(path)-1]
		}
	}
	for v := range g.nodes {
		if _, ok := indices[v]; !ok {
			strongConnect(v)
		}
	}
	return result
}

const INF = int(^uint(0) >> 1) // Maximum value for int, proper infinity representation

// Floyd-Warshall All-Pairs Shortest Paths
func (pg Graph[NodeType, EdgeType]) FloydWarshall() (map[NodeType]map[NodeType]int, error) {
	pg.autoCleanupEdges()
	dist := make(map[NodeType]map[NodeType]int)

	// Initialize distances
	for node := range pg.nodes {
		dist[node] = make(map[NodeType]int)
		for otherNode := range pg.nodes {
			if node == otherNode {
				dist[node][otherNode] = 0
			} else {
				dist[node][otherNode] = INF
			}
		}
	}

	// Set initial edge weights
	for connection, _ := range pg.edges {
		// Use edge.Flow as weight, minimum 1
		weight := 1
		if weight >= INF {
			return nil, errors.New("edge weight too large")
		}
		dist[connection.Source][connection.Target] = weight
	}

	// Floyd-Warshall algorithm
	for k := range pg.nodes {
		for i := range pg.nodes {
			for j := range pg.nodes {
				// Check for INF to prevent overflow
				if dist[i][k] != INF && dist[k][j] != INF {
					newDist := dist[i][k] + dist[k][j]
					// Check for overflow and negative cycles
					if newDist < 0 {
						return nil, errors.New("negative cycle detected")
					}
					if newDist < dist[i][j] {
						dist[i][j] = newDist
					}
				}
			}
		}
	}

	// Verify no negative cycles (optional)
	for node := range pg.nodes {
		if dist[node][node] < 0 {
			return nil, errors.New("negative cycle detected")
		}
	}

	return dist, nil
}

type GraphNodePairEdge[NT comparable, ET any] struct {
	Source, Target NT
	Edge           ET
}

// dfs uses depth first search to loop through the graph and adds each vertex to the stack
func dfs(neighbours [][]int, visited []bool, stack *[]int, node int) {
	if !visited[node] {
		//1
		visited[node] = true
		//2
		for _, neighbour := range neighbours[node] {
			dfs(neighbours, visited, stack, neighbour)
		}
		//3
		(*stack) = append((*stack), node)
	}
}

// transpose transposes (reverses) a directed graph
func (pg Graph[NodeType, EdgeType]) Transpose() Graph[NodeType, EdgeType] {
	pg.autoCleanupEdges()
	npg := NewGraph[NodeType, EdgeType]()

	// Copy nodes
	maps.Copy(npg.nodes, pg.nodes)

	// Add reverse connections
	for connection, edge := range pg.edges {
		npg.edges[NodePair[NodeType]{connection.Target, connection.Source}] = edge
	}
	return npg
}

// transpose transposes a directed graph
func transpose(graph [][]int) [][]int {
	res := make([][]int, len(graph))
	//1
	for el, neighbours := range graph {
		for _, val := range neighbours {
			res[val] = append(res[val], el)
		}
	}
	return res
}

// visit uses dfs to loop through the transposed graph and output strongly connected components
func visit(graph [][]int, visited []bool, node int) []int {
	var results []int
	if !visited[node] {
		//1
		visited[node] = true
		results = append(results, node)

		//2
		for _, neighbour := range graph[node] {
			if !(visited[neighbour]) {
				results = append(results, visit(graph, visited, neighbour)...)
			}
		}
	}
	return results
}

// AdjacencyMap returns the adjacency map - map of Source -> []Target
func (pg Graph[NodeType, EdgeType]) AdjacencyMap() map[NodeType][]NodeType {
	pg.autoCleanupEdges()
	adjacencyMap := make(map[NodeType][]NodeType)
	// Ensure everything is in there
	for id, _ := range pg.nodes {
		adjacencyMap[id] = nil
	}

	// Add every connection
	for connection, _ := range pg.edges {
		adjacencyMap[connection.Source] = append(adjacencyMap[connection.Source], connection.Target)
	}
	return adjacencyMap
}

// PredecessorMap returns the predecessor map - map of Target -> []Source
func (pg Graph[NodeType, EdgeType]) PredecessorMap() map[NodeType][]NodeType {
	pg.autoCleanupEdges()
	predecessorMap := make(map[NodeType][]NodeType)
	// Ensure everything is in there
	for id, _ := range pg.nodes {
		predecessorMap[id] = nil
	}

	// Add every connection
	for connection, _ := range pg.edges {
		predecessorMap[connection.Target] = append(predecessorMap[connection.Target], connection.Source)
	}
	return predecessorMap
}

// SuccessorMap returns the successor map
func (pg Graph[NodeType, EdgeType]) SuccessorMap() map[NodeType][]NodeType {
	pg.autoCleanupEdges()
	successorMap := make(map[NodeType][]NodeType)

	// Ensure every node is in the map
	for id := range pg.nodes {
		successorMap[id] = nil
	}

	// Add every connection
	for connection := range pg.edges {
		successorMap[connection.Source] = append(successorMap[connection.Source], connection.Target)
	}
	return successorMap
}

// TopologicalSort returns the topological sort
func (pg Graph[NodeType, EdgeType]) TopologicalSort() ([]NodeType, error) {
	pg.autoCleanupEdges()
	predecessorMap := pg.PredecessorMap()

	var queue deque.Deque[NodeType]

	for o, predecessors := range predecessorMap {
		if len(predecessors) == 0 {
			queue.PushBack(o)
			delete(predecessorMap, o)
		}
	}

	nodeCount := pg.Order()

	order := make([]NodeType, 0, nodeCount)
	visited := make(map[NodeType]struct{})

	adjacencyMap := pg.AdjacencyMap()

	for queue.Len() > 0 {
		currentObject := queue.PopFront()

		if _, ok := visited[currentObject]; ok {
			continue
		}

		order = append(order, currentObject)
		visited[currentObject] = struct{}{}

		if adjacents, found := adjacencyMap[currentObject]; found {
			for _, adjacentObject := range adjacents {
				if predecessors, found := predecessorMap[adjacentObject]; found {
					if len(predecessors) == 1 {
						queue.PushBack(adjacentObject)
						delete(predecessorMap, adjacentObject)
					} else {
						// Just remove the last one, we're just using this as a counter really
						predecessorMap[adjacentObject] = predecessors[:len(predecessors)-1]
					}
				}
			}
		}
	}

	if len(order) != nodeCount {
		return nil, errors.New("topological sort cannot be computed on graph with cycles")
	}

	return order, nil
}

// StartingNodes returns the starting nodes
func (pg Graph[NodeType, EdgeType]) StartingNodes() []NodeType {
	return pg.outerNodes(false)
}

// EndingNodes returns the ending nodes
func (pg Graph[NodeType, EdgeType]) EndingNodes() []NodeType {
	return pg.outerNodes(true)
}

func (pg Graph[NodeType, EdgeType]) outerNodes(reverse bool) []NodeType {
	pg.autoCleanupEdges()
	pointedTo := make(map[NodeType]struct{})

	for pair, _ := range pg.edges {
		if reverse {
			pointedTo[pair.Source] = struct{}{}
		} else {
			pointedTo[pair.Target] = struct{}{}
		}
	}

	outerNodes := make([]NodeType, 0, len(pg.nodes)-len(pointedTo))
	for node := range pg.nodes {
		if _, found := pointedTo[node]; !found {
			outerNodes = append(outerNodes, node)
		}
	}

	return outerNodes
}

// Islands returns the island nodes that are not connected to anything else
func (pg Graph[NodeType, EdgeType]) Islands() []NodeType {
	pg.autoCleanupEdges()
	pointedToOrFrom := make(map[NodeType]struct{})

	for connections, _ := range pg.edges {
		pointedToOrFrom[connections.Source] = struct{}{}
		pointedToOrFrom[connections.Target] = struct{}{}
	}

	islandNodes := make([]NodeType, 0, len(pg.nodes)-len(pointedToOrFrom))
	for node := range pg.nodes {
		if _, found := pointedToOrFrom[node]; !found {
			islandNodes = append(islandNodes, node)
		}
	}

	return islandNodes
}

// Order returns the number of nodes in the graph.
func (pg Graph[NodeType, EdgeType]) Order() int {
	return len(pg.nodes)
}

// Size returns the number of edges in the graph.
func (pg Graph[NodeType, EdgeType]) Size() int {
	pg.autoCleanupEdges()
	return len(pg.edges)
}

type SCCDAG[NodeType GraphNodeInterface[NodeType], EdgeType GraphEdgeInterface[EdgeType]] struct {
	NodeToSCC map[NodeType]int     // Map each original node to its SCC index
	Edges     map[int]map[int]bool // Edge from SCC i → SCC j
	Nodes     [][]NodeType         // Each SCC as a slice of nodes
}

func CollapseSCCs[NodeType GraphNodeInterface[NodeType], EdgeType GraphEdgeInterface[EdgeType]](sccs [][]NodeType, g Graph[NodeType, EdgeType]) SCCDAG[NodeType, EdgeType] {
	nodeToSCC := make(map[NodeType]int)
	for i, scc := range sccs {
		for _, n := range scc {
			nodeToSCC[n] = i
		}
	}

	edges := make(map[int]map[int]bool)
	for i := range sccs {
		edges[i] = make(map[int]bool)
	}

	// Build SCC-DAG
	for pair := range g.edges {
		srcSCC := nodeToSCC[pair.Source]
		tgtSCC := nodeToSCC[pair.Target]
		if srcSCC != tgtSCC {
			edges[srcSCC][tgtSCC] = true
		}
	}

	return SCCDAG[NodeType, EdgeType]{
		Nodes:     sccs,
		Edges:     edges,
		NodeToSCC: nodeToSCC,
	}
}

func TopoSortDAG[NodeType GraphNodeInterface[NodeType], EdgeType GraphEdgeInterface[EdgeType]](dag SCCDAG[NodeType, EdgeType]) []int {
	indegree := make(map[int]int)
	for i := range dag.Nodes {
		indegree[i] = 0
	}
	for _, targets := range dag.Edges {
		for tgt := range targets {
			indegree[tgt]++
		}
	}

	var queue []int
	for i, deg := range indegree {
		if deg == 0 {
			queue = append(queue, i)
		}
	}

	var order []int
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		order = append(order, u)
		for v := range dag.Edges[u] {
			indegree[v]--
			if indegree[v] == 0 {
				queue = append(queue, v)
			}
		}
	}

	return order
}
