package basedata

import (
	"github.com/lkarlslund/adalanche/modules/version"
	"time"
)

//go:generate msgp
type Common struct {
	Collected time.Time `json:,omitempty`
	Collector string    `json:,omitempty`
	Version   string    `json:,omitempty`
	Commit    string    `json:,omitempty`
}

func GetCommonData() Common {
	return Common{
		Collector: version.Program,
		Version:   version.Version,
		Commit:    version.Commit,
		Collected: time.Now(),
	}
}
