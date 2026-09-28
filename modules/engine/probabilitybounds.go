package engine

// RegisterFixedProbability declares a probability independent of both endpoints
// and other methods. Registering a callback later removes this declaration.
func (pm Edge) RegisterFixedProbability(value Probability) Edge {
	if value < MINPROBABILITY || value > MAXPROBABILITY {
		panic("fixed probability outside supported range")
	}
	edgeInfos[pm].fixedProbability = &value
	edgeInfos[pm].probability = func(*Node, *Node, *EdgeBitmap) Probability { return value }
	return pm
}
