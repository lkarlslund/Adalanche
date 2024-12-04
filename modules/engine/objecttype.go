package engine

import (
	"strings"
	"sync"
)

type ObjectType byte

var (
	NonExistingObjectType                = ^ObjectType(0)
	ObjectTypeOther                      = NewObjectType("Other", "")
	ObjectTypeCallableServicePoint       = NewObjectType("CallableService", "Callable-Service-Point")
	ObjectTypeDomainDNS                  = NewObjectType("DomainDNS", "Domain-DNS")
	ObjectTypeDNSNode                    = NewObjectType("DNSNode", "Dns-Node") //.SetDefault(Last, false)
	ObjectTypeDNSZone                    = NewObjectType("DNSZone", "Dns-Zone") //.SetDefault(Last, false)
	ObjectTypeUser                       = NewObjectType("User", "Person")
	ObjectTypeGroup                      = NewObjectType("Group", "Group")
	ObjectTypeGroupManagedServiceAccount = NewObjectType("GroupManagedServiceAccount", "ms-DS-Group-Managed-Service-Account")
	ObjectTypeManagedServiceAccount      = NewObjectType("ManagedServiceAccount", "ms-DS-Managed-Service-Account")
	ObjectTypeOrganizationalUnit         = NewObjectType("OrganizationalUnit", "Organizational-Unit") //.SetDefault(Last, false)
	ObjectTypeBuiltinDomain              = NewObjectType("BuiltinDomain", "Builtin-Domain")
	ObjectTypeContainer                  = NewObjectType("Container", "Container") //.SetDefault(Last, false)
	ObjectTypeComputer                   = NewObjectType("Computer", "Computer")
	ObjectTypeMachine                    = NewObjectType("Machine", "Machine")
	ObjectTypeGroupPolicyContainer       = NewObjectType("GroupPolicyContainer", "Group-Policy-Container")
	ObjectTypeTrust                      = NewObjectType("Trust", "Trusted-Domain")
	ObjectTypeAttributeSchema            = NewObjectType("AttributeSchema", "Attribute-Schema")
	ObjectTypeClassSchema                = NewObjectType("ClassSchema", "Class-Schema")
	ObjectTypeControlAccessRight         = NewObjectType("ControlAccessRight", "Control-Access-Right")
	ObjectTypeCertificateTemplate        = NewObjectType("CertificateTemplate", "PKI-Certificate-Template")
	ObjectTypePKIEnrollmentService       = NewObjectType("PKIEnrollmentService", "PKI-Enrollment-Service")
	ObjectTypeCertificationAuthority     = NewObjectType("CertificationAuthority", "Certification-Authority")
	ObjectTypeForeignSecurityPrincipal   = NewObjectType("ForeignSecurityPrincipal", "Foreign-Security-Principal")
	ObjectTypeService                    = NewObjectType("Service", "Service")       //.SetDefault(Last, false)
	ObjectTypeExecutable                 = NewObjectType("Executable", "Executable") //.SetDefault(Last, false)
	ObjectTypeDirectory                  = NewObjectType("Directory", "Directory")   //.SetDefault(Last, false)
	ObjectTypeFile                       = NewObjectType("File", "File")             //.SetDefault(Last, false)
)

var objecttypenames = make(map[string]ObjectType)

type objecttypeinfo struct {
	Name           string
	Lookup         string
	DefaultEnabled bool
}

var objecttypenums = []objecttypeinfo{
	{Name: "#OBJECT_TYPE_NOT_FOUND_ERROR#"},
}

var objecttypemutex sync.RWMutex

func NewObjectType(name, lookup string) ObjectType {
	// Lowercase it, everything is case insensitive
	lowercase := strings.ToLower(lookup)

	objecttypemutex.RLock()
	if objecttype, found := objecttypenames[lowercase]; found {
		objecttypemutex.RUnlock()
		return objecttype
	}
	objecttypemutex.RUnlock()
	objecttypemutex.Lock()
	// Retry, someone might have beaten us to it
	if objecttype, found := objecttypenames[lowercase]; found {
		objecttypemutex.Unlock()
		return objecttype
	}

	newindex := ObjectType(len(objecttypenums))

	// both sensitive and insensitive at the same time when adding
	objecttypenames[lowercase] = newindex
	objecttypenames[lookup] = newindex

	objecttypenums = append(objecttypenums, objecttypeinfo{
		Name:           name,
		Lookup:         lookup,
		DefaultEnabled: true,
	})
	objecttypemutex.Unlock()

	return newindex
}

func ObjectTypeLookup(lookup string) (ObjectType, bool) {
	objecttypemutex.RLock()
	objecttype, found := objecttypenames[lookup]
	if found {
		objecttypemutex.RUnlock()
		return objecttype, true
	}

	lowername := strings.ToLower(lookup)
	objecttype, found = objecttypenames[lowername]
	objecttypemutex.RUnlock()
	if found {
		// lowercase version found, add the cased version too
		objecttypemutex.Lock()
		objecttypenames[lookup] = objecttype
		objecttypemutex.Unlock()
		return objecttype, found
	}

	// not found, we don't know what this is, but lets speed this up for next time
	objecttypemutex.Lock()
	objecttypenames[lookup] = ObjectTypeOther
	objecttypemutex.Unlock()

	return ObjectTypeOther, false
}

func (ot ObjectType) String() string {
	return objecttypenums[ot].Name
}

func (ot ObjectType) ValueString() AttributeValueString {
	return NewAttributeValueString(objecttypenums[ot].Lookup)
}

func (ot ObjectType) Lookup() string {
	return objecttypenums[ot].Lookup
}

func (ot ObjectType) SetDefault(enabled bool) ObjectType {
	objecttypemutex.Lock()
	objecttypenums[ot].DefaultEnabled = enabled
	objecttypemutex.Unlock()
	return ot
}

func ObjectTypes() []objecttypeinfo {
	objecttypemutex.RLock()
	defer objecttypemutex.RUnlock()
	return objecttypenums[1:]
}
