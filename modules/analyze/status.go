package analyze

//go:generate go run github.com/dmarkham/enumer -type=WebServiceStatus -output enums.go

type WebServiceStatus int

const (
	NoData WebServiceStatus = iota
	Error
	Loading
	Analyzing
	PostAnalyzing
	Ready
)
