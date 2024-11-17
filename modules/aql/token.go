package aql

import "github.com/timtadh/lexmachine/machines"

type Token struct {
	Type     TokenID
	Value    string
	Native   any
	Position machines.Match
}

func (t Token) Is(id TokenID) bool {
	return t.Type == id
}

func (t Token) String() string {
	return t.Value
}
