//go:build !windows
// +build !windows

package windowssecurity

import (
	"errors"
)

func GetOwnerAndDACL(objectName string, objectType SE_OBJECT_TYPE) (SID, []byte, error) {
	return "", nil, errors.New("Unsupported on this platform")
}
