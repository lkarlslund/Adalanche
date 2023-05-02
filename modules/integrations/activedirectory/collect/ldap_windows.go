package collect

import (
	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/lkarlslund/ldap/v3/gssapi"
)

func GetSSPIClient() (ldap.GSSAPIClient, error) {
	return gssapi.NewSSPIClient()
}
