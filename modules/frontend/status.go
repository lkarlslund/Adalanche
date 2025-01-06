package frontend

//go:generate go run github.com/dmarkham/enumer -type=WebServiceStatus -output status_enums.go

type WebServiceStatus int

const (
	NoData WebServiceStatus = iota
	Error
	Loading
	Analyzing
	PostAnalyzing
	Ready
)
