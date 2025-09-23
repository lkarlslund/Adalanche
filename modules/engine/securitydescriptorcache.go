package engine

import (
	"sync"
)

var (
	securityDescriptorCache sync.Map
)

// Parse and cache security descriptor
func CacheOrParseSecurityDescriptor(rawsd string) (SecurityDescriptor, error) {
	if len(rawsd) == 0 {
		return SecurityDescriptor{}, ErrEmptySecurityDescriptorAttribute
	}

	sd, found := securityDescriptorCache.Load(rawsd)
	if found {
		return sd.(SecurityDescriptor), nil
	}

	newsd, err := ParseSecurityDescriptor([]byte(rawsd))
	if err != nil {
		return newsd, err
	}

	securityDescriptorCache.Store(rawsd, newsd)
	return newsd, err
}
