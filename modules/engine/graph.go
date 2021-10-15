package engine

type GraphObject struct {
	*Object
	Target    bool
	CanExpand int
}

type PwnGraph struct {
	Nodes       []GraphObject
	Connections []PwnConnection // Connection to Methods map
}

type PwnPair struct {
	Source, Target *Object
}

type PwnConnection struct {
	Source, Target *Object
	PwnMethodBitmap
}

func (pg PwnGraph) SCC() [][]*Object {
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
func (pg PwnGraph) Transpose() PwnGraph {
	npg := PwnGraph{
		Nodes:       make([]GraphObject, len(pg.Nodes)),
		Connections: make([]PwnConnection, len(pg.Connections)),
	}
	copy(npg.Nodes, pg.Nodes)
	for i, connection := range pg.Connections {
		npg.Connections[i] = PwnConnection{
			Source:          connection.Target,
			Target:          connection.Source,
			PwnMethodBitmap: connection.PwnMethodBitmap,
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
