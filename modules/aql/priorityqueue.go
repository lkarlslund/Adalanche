package aql

type Priority int

const (
	ShortestFirst Priority = iota
	ProbableShortest
	LongestFirst
	UnlikelyLongest
)

type PriorityQueue struct {
	p     Priority
	items []searchState
}

func (pq *PriorityQueue) Len() int { return len(pq.items) }

func (pq *PriorityQueue) Less(i, j int) bool {
	switch pq.p {
	case ProbableShortest:
		if pq.items[i].currentOverAllProbability > pq.items[j].currentOverAllProbability {
			return true
		}
		if pq.items[i].currentOverAllProbability < pq.items[j].currentOverAllProbability {
			return false
		}
		fallthrough
	case ShortestFirst:
		if pq.items[i].currentTotalDepth < pq.items[j].currentTotalDepth {
			return true
		}
		if pq.items[i].currentTotalDepth > pq.items[j].currentTotalDepth {
			return false
		}
	case UnlikelyLongest:
		if pq.items[i].currentOverAllProbability < pq.items[j].currentOverAllProbability {
			return true
		}
		if pq.items[i].currentOverAllProbability > pq.items[j].currentOverAllProbability {
			return false
		}
		fallthrough
	case LongestFirst:
		if pq.items[i].currentTotalDepth > pq.items[j].currentTotalDepth {
			return true
		}
		if pq.items[i].currentTotalDepth < pq.items[j].currentTotalDepth {
			return false
		}
	}
	// ensure stability
	return pq.items[i].currentObject.ID() < pq.items[j].currentObject.ID()
}

func (pq *PriorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
}

func (pq *PriorityQueue) Push(x searchState) {
	if len(pq.items) == cap(pq.items) {
		newCap := cap(pq.items) * 2
		if newCap == 0 {
			newCap = 1
		}
		newItems := make([]searchState, len(pq.items), newCap)
		copy(newItems, pq.items)
		pq.items = newItems
	}
	pq.items = append(pq.items, x)
	pq.siftUp(len(pq.items) - 1)
}

func (pq *PriorityQueue) Pop() searchState {
	if len(pq.items) == 0 {
		panic("pop from empty priority queue")
	}
	item := pq.items[0]
	pq.items[0] = pq.items[len(pq.items)-1]
	pq.items = pq.items[:len(pq.items)-1]
	pq.siftDown(0)

	if len(pq.items) <= cap(pq.items)/4 {
		newCap := cap(pq.items) / 2
		if newCap < 1 {
			newCap = 1
		}
		newItems := make([]searchState, len(pq.items), newCap)
		copy(newItems, pq.items)
		pq.items = newItems
	}
	return item
}

func (pq *PriorityQueue) siftUp(i int) {
	for {
		parent := (i - 1) / 2
		if parent == i || !pq.Less(i, parent) {
			break
		}
		pq.Swap(i, parent)
		i = parent
	}
}

func (pq *PriorityQueue) siftDown(i int) {
	for {
		left := 2*i + 1
		right := 2*i + 2
		largest := i
		if left < len(pq.items) && pq.Less(left, largest) {
			largest = left
		}
		if right < len(pq.items) && pq.Less(right, largest) {
			largest = right
		}
		if largest == i {
			break
		}
		pq.Swap(i, largest)
		i = largest
	}
}
