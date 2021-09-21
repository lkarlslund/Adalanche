package main

import (
	"math"
)

type nodedistance struct {
	*Object
	distance uint32
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

	q := queue{}

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
				if methodcount == 0 || (methodcount == 1 && detectedmethods.IsSet(PwnACLContainsDeny)) {
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
