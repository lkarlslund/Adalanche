//go:build !windows
// +build !windows

package collect

import (
	"errors"

	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

func Collect() (localmachine.Info, error) {
	return localmachine.Info{}, errors.New("This is not supported on this platform")
}
