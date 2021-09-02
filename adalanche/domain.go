package main

type Forest struct {
	domains []*Domain
	*Objects
}

type Domain struct {
	dnsname string // contoso.local
	rootDSE *Object
	*Objects
}

// Load from compressed format
func (d *Domain) Load(filename string) error {
	return nil
}

// Save to compressed format
func (d *Domain) Save(filename string) error {
	return nil
}

// Load from SysInternals snapshot file
func (d *Domain) ImportDirectoryExplorerSnapshot(filename string) error {
	return nil
}
