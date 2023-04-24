package engine

import "github.com/lkarlslund/adalanche/modules/ui"

type DynamicFields map[string]interface{}

type Graph struct {
	Nodes       []GraphNode
	Connections []GraphEdge // Connection to Methods map
}

func (pg *Graph) AddObject(o *Object) {
	pg.Nodes = append(pg.Nodes, GraphNode{Object: o})
}

func (pg *Graph) AddEdge(source, target *Object, e EdgeBitmap) {
	pg.Connections = append(pg.Connections, GraphEdge{
		Source:     source,
		Target:     target,
		EdgeBitmap: e,
	})
}

func (pg *Graph) Merge(npg Graph) {
	nodemap := make(map[*Object]GraphNode)
	for _, node := range pg.Nodes {
		nodemap[node.Object] = node
	}

	if len(nodemap) != len(pg.Nodes) {
		ui.Fatal().Msg("Nodes not equal")
	}

	pairmap := make(map[ObjectPair]EdgeBitmap)
	for _, connection := range pg.Connections {
		pairmap[ObjectPair{connection.Source, connection.Target}] = connection.EdgeBitmap
	}

	if len(pairmap) != len(pg.Connections) {
		ui.Fatal().Msg("Connections not equal")
	}

	for _, node := range npg.Nodes {
		if e, ok := nodemap[node.Object]; ok {
			if node.Target {
				e.Target = true
				nodemap[node.Object] = e
			}
			if node.CanExpand > e.CanExpand {
				e.CanExpand = node.CanExpand
				nodemap[node.Object] = e
			}
		} else {
			nodemap[node.Object] = node
		}
	}

	for _, connection := range npg.Connections {
		if e, ok := pairmap[ObjectPair{connection.Source, connection.Target}]; ok {
			e.Merge(connection.EdgeBitmap)
			pairmap[ObjectPair{connection.Source, connection.Target}] = e
		} else {
			pairmap[ObjectPair{connection.Source, connection.Target}] = connection.EdgeBitmap
		}
	}

	pg.Nodes = make([]GraphNode, len(nodemap))
	i := 0
	for _, node := range nodemap {
		pg.Nodes[i] = node
		i++
	}

	pg.Connections = make([]GraphEdge, len(pairmap))
	i = 0
	for connection, methods := range pairmap {
		pg.Connections[i] = GraphEdge{
			Source:     connection.Source,
			Target:     connection.Target,
			EdgeBitmap: methods,
		}
		i++
	}
}

func (pg Graph) SCC() [][]*Object {
	offsetmap := make(map[*Object]int)
	for i, o := range pg.Nodes {
		offsetmap[o.Object] = i
	}

	neighbours := make([][]int, len(pg.Nodes))
	for _, connection := range pg.Connections {
		node := offsetmap[connection.Source]
		neighbours[node] = append(neighbours[node], offsetmap[connection.Target])
	}

	// 1
	visited := make([]bool, len(pg.Nodes))
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
	visited = make([]bool, len(pg.Nodes))
	//6

	var results [][]*Object

	for len(stack) != 0 {
		//7
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		//8
		if !visited[v] {
			sccgroup := visit(transposed, visited, v)
			// if len(sccgroup) > 1 {
			objs := make([]*Object, len(sccgroup))
			for i, node := range sccgroup {
				objs[i] = pg.Nodes[node].Object
			}
			// }
			results = append(results, objs)
		}
	}
	return results
}

type GraphNode struct {
	*Object
	DynamicFields
	CanExpand int
	Target    bool
}

func (n *GraphNode) Set(key string, value interface{}) {
	if n.DynamicFields == nil {
		n.DynamicFields = make(DynamicFields)
	}
	n.DynamicFields[key] = value
}

func (n *GraphNode) Get(key string) interface{} {
	if n.DynamicFields == nil {
		return nil
	}
	return n.DynamicFields[key]
}

type GraphEdge struct {
	Source, Target *Object
	DynamicFields
	EdgeBitmap
}

func (e *GraphEdge) Set(key string, value interface{}) {
	if e.DynamicFields == nil {
		e.DynamicFields = make(DynamicFields)
	}
	e.DynamicFields[key] = value
}

func (e *GraphEdge) Get(key string) interface{} {
	if e.DynamicFields == nil {
		return nil
	}
	return e.DynamicFields[key]
}

type ObjectPair struct {
	Source, Target *Object
}

//dfs uses depth first search to loop through the graph and adds each vertex to the stack
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

//transpose transposes a directed graph
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

//transpose transposes (reverses) a directed graph
func (pg Graph) Transpose() Graph {
	npg := Graph{
		Nodes:       make([]GraphNode, len(pg.Nodes)),
		Connections: make([]GraphEdge, len(pg.Connections)),
	}
	copy(npg.Nodes, pg.Nodes)
	for i, connection := range pg.Connections {
		npg.Connections[i] = GraphEdge{
			Source:     connection.Target,
			Target:     connection.Source,
			EdgeBitmap: connection.EdgeBitmap,
		}
	}
	return npg
}

//visit uses dfs to loop through the transposed graph and output strongly connected components
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

func (pg Graph) AdjacencyMap() map[*Object][]*Object {
	adjacencyMap := make(map[*Object][]*Object)
	// Ensure everything is in there
	for _, node := range pg.Nodes {
		adjacencyMap[node.Object] = nil
	}

	// Add every connection
	for _, connection := range pg.Connections {
		adjacencyMap[connection.Source] = append(adjacencyMap[connection.Source], connection.Target)
	}
	return adjacencyMap
}

func (pg Graph) PredecessorMap() map[*Object][]*Object {
	predecessorMap := make(map[*Object][]*Object)
	// Ensure everything is in there
	for _, node := range pg.Nodes {
		predecessorMap[node.Object] = nil
	}

	// Add every connection
	for _, connection := range pg.Connections {
		predecessorMap[connection.Target] = append(predecessorMap[connection.Target], connection.Source)
	}
	return predecessorMap
}

func (pg Graph) Order() int {
	return len(pg.Nodes)
}
