//go:build !windows
// +build !windows

package collect

import (
	"errors"
	ldap "github.com/lkarlslund/ldap/v3"
)

func GetSSPIClient() (ldap.GSSAPIClient, error) {
	return nil, errors.New("This is only supported on Windows")
}
