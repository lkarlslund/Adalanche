package aql

import "github.com/timtadh/lexmachine/machines"

type Token struct {
	Native   any
	Value    string
	Position machines.Match
	Type     TokenID
}

func (t Token) Is(id TokenID) bool {
	return t.Type == id
}
func (t Token) String() string {
	return t.Value
}
