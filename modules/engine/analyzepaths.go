package engine

import (
	"math"
)

type nodedistance struct {
	*Object
	distance uint32
}

type heapqueue struct {
	items []nodedistance
}

// Enqueue inserts a node in a heap
func (hq *heapqueue) Push(o *Object, distance uint32) {
	hq.items = append(hq.items, nodedistance{o, distance})
	hq.minHeapify()
}

func (hq *heapqueue) minHeapify() {
	idx := len(hq.items) - 1
	element := hq.items[idx]
	for idx > 0 {
		parentIdx := (idx - 1) / 2
		parent := hq.items[parentIdx]
		if element.distance >= parent.distance {
			break
		}
		hq.items[parentIdx] = element
		hq.items[idx] = parent
		idx = parentIdx
	}
}

func (hq *heapqueue) Empty() bool {
	if len(hq.items) == 0 || hq.items[0].Object == nil {
		return true
	}
	return false
}

// Dequeue will remove a node from heap
func (hq *heapqueue) Pop() nodedistance {
	if hq.Empty() {
		// empty
		return nodedistance{}
	}

	min := hq.items[0]
	end := hq.items[len(hq.items)-1]
	hq.items = hq.items[0 : len(hq.items)-1]
	if len(hq.items) > 0 {
		hq.items[0] = end
		hq.bubbleDown()
	}
	return min
}

func (hq *heapqueue) bubbleDown() {
	idx := 0
	length := len(hq.items)
	element := hq.items[0]
	for {
		leftChildIdx := (2 * idx) + 1
		rightChildIdx := (2 * idx) + 2
		var leftChild, rightChild nodedistance
		var swap int

		if leftChildIdx < length {
			leftChild = hq.items[leftChildIdx]
			if leftChild.distance < element.distance {
				swap = leftChildIdx
			}
		}
		if rightChildIdx < length {
			rightChild = hq.items[rightChildIdx]
			if (rightChild.distance < element.distance && swap == 0) || (rightChild.distance < leftChild.distance && swap != 0) {
				swap = rightChildIdx
			}
		}

		if swap == 0 {
			break
		}
		hq.items[idx] = hq.items[swap]
		hq.items[swap] = element
		idx = swap
	}
}

type queue struct {
	items []nodedistance
}

func (q *queue) Push(o *Object, distance uint32) {
	// Grow queue chunkwise
	if len(q.items) == cap(q.items) {
		nq := make([]nodedistance, len(q.items), len(q.items)+16)
		copy(nq, q.items)
		q.items = nq
	}

	numitems := len(q.items)
	if numitems == 0 {
		q.items = append(q.items, nodedistance{o, distance})
		return
	}

	insertat := 0

	if distance <= q.items[0].distance {
		insertat = 0
	} else if q.items[numitems-1].distance <= distance {
		q.items = append(q.items, nodedistance{o, distance})
		return
	} else {
		// Not the first one ... see where then ...
		for i := 1; i < len(q.items); i++ {
			if q.items[i].distance <= distance && distance <= q.items[i+1].distance {
				insertat = i
				break
			}
		}
	}

	q.items = q.items[:len(q.items)+1]
	copy(q.items[insertat+1:], q.items[insertat:])
	q.items[insertat] = nodedistance{o, distance}
}

func (q *queue) Pop() nodedistance {
	if len(q.items) == 0 {
		return nodedistance{}
	}
	r := q.items[0]
	q.items = q.items[1:]
	return r
}

func (q queue) Empty() bool {
	return len(q.items) == 0
}

func AnalyzePaths(start, end *Object, obs *Objects, lookformethods PwnMethodBitmap, minprobability Probability, iterations int) PwnGraph {
	visited := make(map[*Object]struct{})
	dist := make(map[*Object]uint32)
	prev := make(map[*Object]*Object)

	q := heapqueue{}
	// q := queue{}

	dist[start] = 0

	q.Push(start, 0)

	for !q.Empty() {
		v := q.Pop()

		source := v.Object

		if _, found := visited[source]; found {
			continue
		}

		visited[source] = struct{}{}

		for target, methods := range source.CanPwn {
			if _, found := visited[target]; !found {

				// If this is not a chosen method, skip it
				detectedmethods := methods.Intersect(lookformethods)

				methodcount := detectedmethods.Count()
				if methodcount == 0 {
					// Nothing useful or just a deny ACL, skip it
					continue
				}

				prob := detectedmethods.MaxProbabiltity(v.Object, target)
				if prob < minprobability {
					// Skip entirely if too
					continue
				}

				weight := uint32(101 - prob)

				sdist, sfound := dist[source]
				if !sfound {
					sdist = math.MaxUint32
				}
				tdist, tfound := dist[target]
				if !tfound {
					tdist = math.MaxUint32
				}

				if sdist+weight < tdist {
					prev[target] = source
					dist[target] = sdist + weight
					q.Push(target, sdist+weight)
				}
			}
		}
	}

	if prev[end] == nil {
		// No results
		return PwnGraph{}
	}

	var result PwnGraph
	result.Nodes = append(result.Nodes, GraphObject{
		Object:    end,
		Target:    true,
		CanExpand: 0,
	})

	curnode := end
	prenode := prev[end]
	for {
		result.Nodes = append(result.Nodes, GraphObject{
			Object:    prenode,
			Target:    false,
			CanExpand: 0,
		})
		result.Connections = append(result.Connections,
			PwnConnection{
				Source:          prenode,
				Target:          curnode,
				PwnMethodBitmap: prenode.CanPwn[curnode],
			})
		if prenode == start {
			break
		}
		curnode = prenode
		prenode = prev[curnode]
	}

	return result
}
