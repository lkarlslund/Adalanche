//go:build !windows
// +build !windows

package collect

func init() {
	CreateDumper = func(opts LDAPOptions) LDAPDumper {
		return &AD{
			LDAPOptions: opts,
		}
	}
}