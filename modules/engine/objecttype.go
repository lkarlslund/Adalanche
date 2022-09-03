package engine

import (
	"strings"
	"sync"
)

type PriorityFML byte

const (
	First PriorityFML = iota
	Middle
	Last
)

type ObjectType byte

var (
	ObjectTypeOther                      = NewObjectType("Other", "")
	ObjectTypeDomainDNS                  = NewObjectType("DomainDNS", "Domain-DNS")
	ObjectTypeDNSNode                    = NewObjectType("DNSNode", "Dns-Node").SetDefault(Last, false)
	ObjectTypeDNSZone                    = NewObjectType("DNSZone", "Dns-Zone").SetDefault(Last, false)
	ObjectTypeUser                       = NewObjectType("User", "Person")
	ObjectTypeGroup                      = NewObjectType("Group", "Group")
	ObjectTypeForeignSecurityPrincipal   = NewObjectType("ForeignSecurityPrincipal", "Foreign-Security-Principal")
	ObjectTypeGroupManagedServiceAccount = NewObjectType("GroupManagedServiceAccount", "ms-DS-Group-Managed-Service-Account")
	ObjectTypeManagedServiceAccount      = NewObjectType("ManagedServiceAccount", "ms-DS-Managed-Service-Account")
	ObjectTypeOrganizationalUnit         = NewObjectType("OrganizationalUnit", "Organizational-Unit").SetDefault(Last, false)
	ObjectTypeBuiltinDomain              = NewObjectType("BuiltinDomain", "Builtin-Domain")
	ObjectTypeContainer                  = NewObjectType("Container", "Container").SetDefault(Last, false)
	ObjectTypeComputer                   = NewObjectType("Computer", "Computer")
	ObjectTypeGroupPolicyContainer       = NewObjectType("GroupPolicyContainer", "Group-Policy-Container")
	ObjectTypeTrust                      = NewObjectType("Trust", "Trusted-Domain")
	ObjectTypeAttributeSchema            = NewObjectType("AttributeSchema", "Attribute-Schema")
	ObjectTypeClassSchema                = NewObjectType("ClassSchema", "Class-Schema")
	ObjectTypeControlAccessRight         = NewObjectType("ControlAccessRight", "Control-Access-Right")
	ObjectTypeCertificateTemplate        = NewObjectType("CertificateTemplate", "PKI-Certificate-Template")
	ObjectTypePKIEnrollmentService       = NewObjectType("PKIEnrollmentService", "PKI-Enrollment-Service")
	ObjectTypeCertificationAuthority     = NewObjectType("CertificationAuthority", "Certification-Authority")
	ObjectTypeService                    = NewObjectType("Service", "Service").SetDefault(Last, false)
	ObjectTypeExecutable                 = NewObjectType("Executable", "Executable").SetDefault(Last, false)
	ObjectTypeDirectory                  = NewObjectType("Directory", "Directory").SetDefault(Last, false)
	ObjectTypeFile                       = NewObjectType("File", "File").SetDefault(Last, false)
)

var objecttypenames = make(map[string]ObjectType)

type objecttypeinfo struct {
	Name            string
	Lookup          string
	DefaultEnabledF bool
	DefaultEnabledM bool
	DefaultEnabledL bool
}

var objecttypenums = []objecttypeinfo{
	{Name: "#OBJECT_TYPE_NOT_FOUND_ERROR#"},
}

var objecttypemutex sync.RWMutex

func NewObjectType(name, lookup string) ObjectType {
	// Lowercase it, everything is case insensitive
	lookup = strings.ToLower(lookup)

	objecttypemutex.RLock()
	if objecttype, found := objecttypenames[lookup]; found {
		objecttypemutex.RUnlock()
		return objecttype
	}
	objecttypemutex.RUnlock()
	objecttypemutex.Lock()
	// Retry, someone might have beaten us to it
	if objecttype, found := objecttypenames[lookup]; found {
		objecttypemutex.Unlock()
		return objecttype
	}

	newindex := ObjectType(len(objecttypenums))
	objecttypenames[lookup] = newindex
	objecttypenums = append(objecttypenums, objecttypeinfo{
		Name:            name,
		Lookup:          lookup,
		DefaultEnabledF: true,
		DefaultEnabledM: true,
		DefaultEnabledL: true,
	})
	objecttypemutex.Unlock()

	return newindex
}

func ObjectTypeLookup(lookup string) (ObjectType, bool) {
	lowername := strings.ToLower(lookup)

	objecttypemutex.RLock()
	objecttype, found := objecttypenames[lowername]
	objecttypemutex.RUnlock()
	if !found {
		return ObjectTypeOther, false
	}
	return objecttype, found
}

func (ot ObjectType) String() string {
	return objecttypenums[ot].Name
}

func (ot ObjectType) Lookup() string {
	return objecttypenums[ot].Lookup
}

func (ot ObjectType) SetDefault(p PriorityFML, enabled bool) ObjectType {
	objecttypemutex.Lock()
	defer objecttypemutex.Unlock()
	switch p {
	case First:
		objecttypenums[ot].DefaultEnabledF = enabled
	case Middle:
		objecttypenums[ot].DefaultEnabledM = enabled
	case Last:
		objecttypenums[ot].DefaultEnabledL = enabled
	}
	return ot
}

func ObjectTypes() []objecttypeinfo {
	objecttypemutex.RLock()
	defer objecttypemutex.RUnlock()
	return objecttypenums[1:]
}
