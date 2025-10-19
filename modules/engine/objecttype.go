package engine

import (
	"strings"
	"sync"
)

type NodeType byte

var (
	NonExistingObjectType              = ^NodeType(0)
	NodeTypeOther                      = NewObjectType("Other", "")
	NodeTypeCallableServicePoint       = NewObjectType("CallableService", "Callable-Service-Point")
	NodeTypeDomainDNS                  = NewObjectType("DomainDNS", "Domain-DNS")
	NodeTypeDNSNode                    = NewObjectType("DNSNode", "Dns-Node") //.SetDefault(Last, false)
	NodeTypeDNSZone                    = NewObjectType("DNSZone", "Dns-Zone") //.SetDefault(Last, false)
	NodeTypeUser                       = NewObjectType("User", "Person")
	NodeTypeGroup                      = NewObjectType("Group", "Group")
	NodeTypeGroupManagedServiceAccount = NewObjectType("GroupManagedServiceAccount", "ms-DS-Group-Managed-Service-Account")
	NodeTypeManagedServiceAccount      = NewObjectType("ManagedServiceAccount", "ms-DS-Managed-Service-Account")
	NodeTypeOrganizationalUnit         = NewObjectType("OrganizationalUnit", "Organizational-Unit") //.SetDefault(Last, false)
	NodeTypeBuiltinDomain              = NewObjectType("BuiltinDomain", "Builtin-Domain")
	NodeTypeContainer                  = NewObjectType("Container", "Container") //.SetDefault(Last, false)
	NodeTypeComputer                   = NewObjectType("Computer", "Computer")
	NodeTypeMachine                    = NewObjectType("Machine", "Machine")
	NodeTypeGroupPolicyContainer       = NewObjectType("GroupPolicyContainer", "Group-Policy-Container")
	NodeTypeTrust                      = NewObjectType("Trust", "Trusted-Domain")
	NodeTypeAttributeSchema            = NewObjectType("AttributeSchema", "Attribute-Schema")
	NodeTypeClassSchema                = NewObjectType("ClassSchema", "Class-Schema")
	NodeTypeControlAccessRight         = NewObjectType("ControlAccessRight", "Control-Access-Right")
	NodeTypeCertificateTemplate        = NewObjectType("CertificateTemplate", "PKI-Certificate-Template")
	NodeTypePKIEnrollmentService       = NewObjectType("PKIEnrollmentService", "PKI-Enrollment-Service")
	NodeTypeCertificationAuthority     = NewObjectType("CertificationAuthority", "Certification-Authority")
	NodeTypeForeignSecurityPrincipal   = NewObjectType("ForeignSecurityPrincipal", "Foreign-Security-Principal")
	NodeTypeService                    = NewObjectType("Service", "Service")       //.SetDefault(Last, false)
	NodeTypeExecutable                 = NewObjectType("Executable", "Executable") //.SetDefault(Last, false)
	NodeTypeDirectory                  = NewObjectType("Directory", "Directory")   //.SetDefault(Last, false)
	NodeTypeFile                       = NewObjectType("File", "File")             //.SetDefault(Last, false)
)

var nodeTypeNames = make(map[string]NodeType)

type nodeTypeInfo struct {
	Name           string
	Lookup         string
	DefaultEnabled bool
}

var nodeTypeNums = []nodeTypeInfo{
	{Name: "#OBJECT_TYPE_NOT_FOUND_ERROR#"},
}

var nodeTypeMutex sync.RWMutex

func NewObjectType(name, lookup string) NodeType {
	// Lowercase it, everything is case insensitive
	lowercase := strings.ToLower(lookup)

	nodeTypeMutex.RLock()
	if nodeType, found := nodeTypeNames[lowercase]; found {
		nodeTypeMutex.RUnlock()
		return nodeType
	}
	nodeTypeMutex.RUnlock()
	nodeTypeMutex.Lock()
	// Retry, someone might have beaten us to it
	if nodeType, found := nodeTypeNames[lowercase]; found {
		nodeTypeMutex.Unlock()
		return nodeType
	}

	newindex := NodeType(len(nodeTypeNums))

	// both sensitive and insensitive at the same time when adding
	nodeTypeNames[lowercase] = newindex
	nodeTypeNames[lookup] = newindex

	nodeTypeNums = append(nodeTypeNums, nodeTypeInfo{
		Name:           name,
		Lookup:         lookup,
		DefaultEnabled: true,
	})
	nodeTypeMutex.Unlock()

	return newindex
}

func NodeTypeLookup(lookup string) (NodeType, bool) {
	nodeTypeMutex.RLock()
	objecttype, found := nodeTypeNames[lookup]
	if found {
		nodeTypeMutex.RUnlock()
		return objecttype, true
	}

	lowername := strings.ToLower(lookup)
	objecttype, found = nodeTypeNames[lowername]
	nodeTypeMutex.RUnlock()
	if found {
		// lowercase version found, add the cased version too
		nodeTypeMutex.Lock()
		nodeTypeNames[lookup] = objecttype
		nodeTypeMutex.Unlock()
		return objecttype, found
	}

	// not found, we don't know what this is, but lets speed this up for next time
	nodeTypeMutex.Lock()
	nodeTypeNames[lookup] = NodeTypeOther
	nodeTypeMutex.Unlock()

	return NodeTypeOther, false
}

func (ot NodeType) String() string {
	return nodeTypeNums[ot].Name
}

func (ot NodeType) ValueString() attributeValueString {
	return AttributeValueString(nodeTypeNums[ot].Lookup)
}

func (ot NodeType) Lookup() string {
	return nodeTypeNums[ot].Lookup
}

func (ot NodeType) SetDefault(enabled bool) NodeType {
	nodeTypeMutex.Lock()
	nodeTypeNums[ot].DefaultEnabled = enabled
	nodeTypeMutex.Unlock()
	return ot
}

func NodeTypes() []nodeTypeInfo {
	nodeTypeMutex.RLock()
	defer nodeTypeMutex.RUnlock()
	return nodeTypeNums[1:]
}
