package engine

// go install github.com/dmarkham/enumer

//go:generate go tool github.com/dmarkham/enumer -type=EdgeDirection -output edgedirection_enums.go -json

type EdgeDirection int

const (
	Out EdgeDirection = 0
	In  EdgeDirection = 1
	Any EdgeDirection = 9
)
