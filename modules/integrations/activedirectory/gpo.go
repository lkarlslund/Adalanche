package activedirectory

import (
	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"time"
)

type GPOdump struct {
	basedata.Common
	GPOinfo
}
type GPOinfo struct {
	DomainDN      string        `json:",omitempty"`
	DomainNetbios string        `json:",omitempty"`
	Path          string        `json:",omitempty"`
	Files         []GPOfileinfo `json:",omitempty"`
	GUID          uuid.UUID     `json:",omitempty"`
}
type GPOfileinfo struct {
	Timestamp    time.Time
	RelativePath string              `json:",omitempty"`
	OwnerSID     windowssecurity.SID `json:",omitempty"`
	DACL         []byte              `json:",omitempty"`
	Contents     []byte              `json:",omitempty"`
	Size         int64               `json:",omitempty"`
	IsDir        bool                `json:",omitempty"`
}
