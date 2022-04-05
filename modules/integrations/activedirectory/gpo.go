package activedirectory

import (
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

type GPOdump struct {
	basedata.Common
	GPOinfo
}

type GPOinfo struct {
	GUID          uuid.UUID     `json:",omitempty"`
	DomainDN      string        `json:",omitempty"`
	DomainNetbios string        `json:",omitempty"`
	Path          string        `json:",omitempty"`
	Files         []GPOfileinfo `json:",omitempty"`
}

type GPOfileinfo struct {
	RelativePath string `json:",omitempty"`
	IsDir        bool   `json:",omitempty"`

	Size      int64               `json:",omitempty"`
	Timestamp time.Time           `json:",omitempty"`
	OwnerSID  windowssecurity.SID `json:",omitempty"`
	DACL      []byte              `json:",omitempty"`

	Contents []byte `json:",omitempty"`
}
