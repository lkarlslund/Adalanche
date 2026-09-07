package basedata

import (
	"time"

	"github.com/lkarlslund/adalanche/modules/version"
)

//go:generate go tool github.com/tinylib/msgp
type Common struct {
	Collected time.Time `json:",omitempty"`
	Collector string    `json:",omitempty"`
	Version   string    `json:",omitempty"`
	Commit    string    `json:",omitempty"`
}

// CollectionStatus describes acquisition, not the security of the collected value.
// The zero value means that acquisition history is unknown.
type CollectionStatus string

const (
	CollectionUnknown      CollectionStatus = ""
	CollectionCollected    CollectionStatus = "collected"
	CollectionNotFound     CollectionStatus = "not_found"
	CollectionAccessDenied CollectionStatus = "access_denied"
	CollectionUnsupported  CollectionStatus = "unsupported"
	CollectionFailed       CollectionStatus = "failed"
	CollectionCanceled     CollectionStatus = "canceled"
	CollectionTimedOut     CollectionStatus = "timed_out"
	CollectionNotRequested CollectionStatus = "not_requested"
)

// CollectionResult records one operation. ErrorCode is a machine-readable code,
// never an error message that might contain collected values or credentials.
type CollectionResult struct {
	Status    CollectionStatus
	ErrorCode string `json:",omitempty"`
}

// CollectionResults is keyed by operation and source-relative target. A missing
// entry means unknown, including in older dumps. Successful enumeration does not
// imply that every property of every enumerated item was read successfully.
type CollectionResults map[string]CollectionResult

func GetCommonData() Common {
	return Common{
		Collector: version.Program,
		Version:   version.Version,
		Commit:    version.Commit,
		Collected: time.Now(),
	}
}
