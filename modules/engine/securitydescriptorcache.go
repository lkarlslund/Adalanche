package engine

import (
	"sync"

	"github.com/OneOfOne/xxhash"
)

var (
	securitydescriptorcachemutex sync.RWMutex
	securityDescriptorCache      = make(map[uint64]*SecurityDescriptor)
)

// Parse and cache security descriptor
func CacheOrParseSecurityDescriptor(rawsd []byte) (*SecurityDescriptor, error) {
	if len(rawsd) == 0 {
		return nil, ErrEmptySecurityDescriptorAttribute
	}

	securitydescriptorcachemutex.RLock()
	cacheindex := xxhash.Checksum64(rawsd)
	if sd, found := securityDescriptorCache[cacheindex]; found {
		securitydescriptorcachemutex.RUnlock()
		return sd, nil
	}
	securitydescriptorcachemutex.RUnlock()

	securitydescriptorcachemutex.Lock()
	sd, err := ParseSecurityDescriptor([]byte(rawsd))
	if err == nil {
		securityDescriptorCache[cacheindex] = &sd
	}

	securitydescriptorcachemutex.Unlock()
	return &sd, err
}
