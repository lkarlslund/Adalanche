//go:build !windows
// +build !windows

package collect

func GetSSPIClient() (ldap.GSSAPIClient, error) {
	return nil, errors.New("This is only supported on Windows")
}
