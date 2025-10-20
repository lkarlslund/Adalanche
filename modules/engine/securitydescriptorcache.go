package engine

import gsync "github.com/SaveTheRbtz/generic-sync-map-go"

var (
	securityDescriptorCache gsync.MapOf[string, *SecurityDescriptor]
)

// Parse and cache security descriptor
func CacheOrParseSecurityDescriptor(rawsd string) (*SecurityDescriptor, error) {
	if len(rawsd) == 0 {
		return nil, ErrEmptySecurityDescriptorAttribute
	}

	sd, found := securityDescriptorCache.Load(rawsd)
	if found {
		return sd, nil
	}

	newsd, err := ParseSecurityDescriptor([]byte(rawsd))
	if err != nil {
		return &newsd, err
	}

	securityDescriptorCache.Store(rawsd, &newsd)
	return &newsd, err
}
