package engine

import (
	"sync"
)

var (
	securityDescriptorCache sync.Map
)

// Parse and cache security descriptor
func CacheOrParseSecurityDescriptor(rawsd string) (*SecurityDescriptor, error) {
	if len(rawsd) == 0 {
		return nil, ErrEmptySecurityDescriptorAttribute
	}

	newsd := &SecurityDescriptor{
		Raw: rawsd,
	}

	sd, found := securityDescriptorCache.LoadOrStore(rawsd, newsd)
	if found {
		return sd.(*SecurityDescriptor), nil
	}

	err := newsd.Parse()
	return newsd, err
}
