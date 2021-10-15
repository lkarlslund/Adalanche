package basedata

import (
	"time"

	"github.com/lkarlslund/adalanche/modules/version"
)

type Common struct {
	Collector string    `json:,omitempty`
	BuildDate string    `json:,omitempty`
	Commit    string    `json:,omitempty`
	Collected time.Time `json:,omitempty`
}

func GetCommonData() Common {
	return Common{
		Collector: version.Programname,
		BuildDate: version.Builddate,
		Commit:    version.Commit,
		Collected: time.Now(),
	}
}
