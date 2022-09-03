package basedata

import (
	"time"

	"github.com/lkarlslund/adalanche/modules/version"
)

//go:generate msgp

type Common struct {
	Collector string    `json:,omitempty`
	Version   string    `json:,omitempty`
	Commit    string    `json:,omitempty`
	Collected time.Time `json:,omitempty`
}

func GetCommonData() Common {
	return Common{
		Collector: version.Program,
		Version:   version.Version,
		Commit:    version.Commit,
		Collected: time.Now(),
	}
}
