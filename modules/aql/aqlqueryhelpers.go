package aql

type Priority int

const (
	ShortestFirst Priority = iota
	ProbableShortest
	LongestFirst
	UnlikelyLongest
)
