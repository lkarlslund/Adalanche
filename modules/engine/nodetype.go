package engine

import (
	"strings"
	"sync"
)

type NodeType byte

var (
	NonExistingObjectType              = ^NodeType(0)
	NodeTypeOther                      = NewObjectType("Other", "")
	NodeTypeCallableServicePoint       = NewObjectType("CallableService", "Callable-Service-Point").SetDisplayName("CallableService").SetIcon("icons/service.svg").SetBackgroundColor("#90ee90").SetDescription("Callable service endpoints.")
	NodeTypeDomainDNS                  = NewObjectType("DomainDNS", "Domain-DNS")
	NodeTypeDNSNode                    = NewObjectType("DNSNode", "Dns-Node").SetDisplayName("DNS-Node").SetIcon("icons/dns.svg").SetDescription("DNS records and nodes.") //.SetDefault(Last, false)
	NodeTypeDNSZone                    = NewObjectType("DNSZone", "Dns-Zone")                                                                                              //.SetDefault(Last, false)
	NodeTypeUser                       = NewObjectType("User", "Person").SetDisplayName("Person").SetIcon("icons/person-fill.svg").SetBackgroundColor("#16a34a").SetDescription("User and identity principals.")
	NodeTypeGroup                      = NewObjectType("Group", "Group").SetDisplayName("Group").SetIcon("icons/people-fill.svg").SetBackgroundColor("#f59e0b").SetDescription("Security and distribution groups.")
	NodeTypeGroupManagedServiceAccount = NewObjectType("GroupManagedServiceAccount", "ms-DS-Group-Managed-Service-Account").SetDisplayName("Group Managed Service Account").SetIcon("icons/manage_accounts_black_24dp.svg").SetBackgroundColor("#90ee90").SetDescription("Group managed service accounts.")
	NodeTypeManagedServiceAccount      = NewObjectType("ManagedServiceAccount", "ms-DS-Managed-Service-Account").SetDisplayName("Managed Service Account").SetIcon("icons/manage_accounts_black_24dp.svg").SetBackgroundColor("#90ee90").SetDescription("Managed service accounts.")
	NodeTypeOrganizationalUnit         = NewObjectType("OrganizationalUnit", "Organizational-Unit").SetDisplayName("Organizational Unit").SetIcon("icons/source_black_24dp.svg").SetBackgroundColor("#d1d5db").SetDescription("Organizational units and directory containers.") //.SetDefault(Last, false)
	NodeTypeBuiltinDomain              = NewObjectType("BuiltinDomain", "Builtin-Domain")
	NodeTypeContainer                  = NewObjectType("Container", "Container").SetDisplayName("Container").SetIcon("icons/folder_black_24dp.svg").SetBackgroundColor("#d1d5db").SetDescription("Generic directory containers.") //.SetDefault(Last, false)
	NodeTypeComputer                   = NewObjectType("Computer", "Computer").SetDisplayName("Computer").SetIcon("icons/tv-fill.svg").SetBackgroundColor("#90ee90").SetDescription("Computer accounts and workstation objects.")
	NodeTypeMachine                    = NewObjectType("Machine", "Machine").SetDisplayName("Machine").SetIcon("icons/tv-fill.svg").SetBackgroundColor("#0f766e").SetDescription("Local machine entities outside directory computer accounts.")
	NodeTypeGroupPolicyContainer       = NewObjectType("GroupPolicyContainer", "Group-Policy-Container").SetDisplayName("Group Policy Container").SetIcon("icons/gpo.svg").SetBackgroundColor("#9333ea").SetDescription("Group Policy containers.")
	NodeTypeTrust                      = NewObjectType("Trust", "Trusted-Domain")
	NodeTypeAttributeSchema            = NewObjectType("AttributeSchema", "Attribute-Schema")
	NodeTypeClassSchema                = NewObjectType("ClassSchema", "Class-Schema")
	NodeTypeControlAccessRight         = NewObjectType("ControlAccessRight", "Control-Access-Right")
	NodeTypeCertificateTemplate        = NewObjectType("CertificateTemplate", "PKI-Certificate-Template").SetDisplayName("Certificate Template").SetIcon("icons/certificate.svg").SetBackgroundColor("#f9a8d4").SetDescription("Certificate templates.")
	NodeTypePKIEnrollmentService       = NewObjectType("PKIEnrollmentService", "PKI-Enrollment-Service")
	NodeTypeCertificationAuthority     = NewObjectType("CertificationAuthority", "Certification-Authority")
	NodeTypeForeignSecurityPrincipal   = NewObjectType("ForeignSecurityPrincipal", "Foreign-Security-Principal").SetDisplayName("Foreign Security Principal").SetIcon("icons/badge_black_24dp.svg").SetBackgroundColor("#90ee90").SetDescription("External or foreign security principals.")
	NodeTypeService                    = NewObjectType("Service", "Service").SetDisplayName("Service").SetIcon("icons/service.svg").SetBackgroundColor("#90ee90").SetDescription("Service identities and service definitions.")                  //.SetDefault(Last, false)
	NodeTypeExecutable                 = NewObjectType("Executable", "Executable").SetDisplayName("Executable").SetIcon("icons/binary-code.svg").SetBackgroundColor("#90ee90").SetDescription("Executable files and binaries.")                  //.SetDefault(Last, false)
	NodeTypeDirectory                  = NewObjectType("Directory", "Directory").SetDisplayName("Directory").SetIcon("icons/source_black_24dp.svg").SetBackgroundColor("#93c5fd").SetDescription("Directory or folder-like filesystem objects.") //.SetDefault(Last, false)
	NodeTypeFile                       = NewObjectType("File", "File").SetDisplayName("File").SetIcon("icons/article_black_24dp.svg").SetBackgroundColor("#93c5fd").SetDescription("File objects.")                                              //.SetDefault(Last, false)
)

var nodeTypeNames = make(map[string]NodeType)

type nodeTypeInfo struct {
	Name            string
	Lookup          string
	DefaultEnabled  bool
	DisplayName     string
	Icon            string
	BackgroundColor string
	Description     string
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

func (ot NodeType) ValueString() AttributeValue {
	return NV(nodeTypeNums[ot].Lookup)
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

func (ot NodeType) SetIcon(icon string) NodeType {
	nodeTypeMutex.Lock()
	nodeTypeNums[ot].Icon = icon
	nodeTypeMutex.Unlock()
	return ot
}

func (ot NodeType) SetDisplayName(name string) NodeType {
	nodeTypeMutex.Lock()
	nodeTypeNums[ot].DisplayName = name
	nodeTypeMutex.Unlock()
	return ot
}

func (ot NodeType) SetBackgroundColor(color string) NodeType {
	nodeTypeMutex.Lock()
	nodeTypeNums[ot].BackgroundColor = color
	nodeTypeMutex.Unlock()
	return ot
}

func (ot NodeType) SetDescription(description string) NodeType {
	nodeTypeMutex.Lock()
	nodeTypeNums[ot].Description = description
	nodeTypeMutex.Unlock()
	return ot
}

func NodeTypes() []nodeTypeInfo {
	nodeTypeMutex.RLock()
	defer nodeTypeMutex.RUnlock()
	return nodeTypeNums[1:]
}
