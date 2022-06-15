package engine

import (
	"sync"
)

var (
	securitydescriptorcachemutex sync.RWMutex
	securityDescriptorCache      = make(map[uint64]*SecurityDescriptor)

	// AllRights           = make(map[uuid.UUID]*Object) // Extented-Rights from Configuration - rightsGUID -> object
	// AllSchemaClasses    = make(map[uuid.UUID]*Object) // schemaIdGUID -> object
	// AllSchemaAttributes = make(map[uuid.UUID]*Object) // attribute ...
)
