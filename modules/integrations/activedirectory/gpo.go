package activedirectory

import (
	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

type GPOdump struct {
	basedata.Common
	GPOinfo
}

type GPOinfo struct {
	GUID  uuid.UUID     `json:",omitempty"`
	Path  string        `json:",omitempty"`
	Files []GPOfileinfo `json:",omitempty"`
}

type GPOfileinfo struct {
	RelativePath string `json:",omitempty"`
	IsDir        bool   `json:",omitempty"`

	OwnerSID windowssecurity.SID `json:",omitempty"`
	DACL     []byte              `json:",omitempty"`

	Contents []byte `json:",omitempty"`
}
