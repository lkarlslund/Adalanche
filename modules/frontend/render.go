package frontend

type typeinfo struct {
	Name string
	Icon string
}

var typeInfos = map[string]typeinfo{
	"User": {
		Name: "User",
		Icon: "icons/person-fill.svg",
	},
	"Group": {
		Name: "Group",
		Icon: "icons/people-fill.svg",
	},
	"Computer": {
		Name: "Computer",
		Icon: "icons/computer-fill.svg",
	},
	"Machine": {
		Name: "Machine",
		Icon: "icons/tv-fill.svg",
	},
	"ManagedServiceAccount": {
		Name: "Managed Service Account",
		Icon: "icons/manage_accounts_black_24dp.svg",
	},
	"GroupManagedServiceAccount": {
		Name: "Group Managed Service Account",
		Icon: "icons/manage_accounts_black_24dp.svg",
	},
	"ForeignSecurityPrincipal": {
		Name: "Foreign Security Principal",
		Icon: "icons/badge_black_24dp.svg",
	},
	"Service": {
		Name: "Service",
		Icon: "icons/service.svg",
	},
	"Directory": {
		Name: "Directory",
		Icon: "icons/source_black_24dp.svg",
	},
	"File": {
		Name: "File",
		Icon: "icons/source_black_24dp.svg",
	},
	"Executable": {
		Name: "Executable",
		Icon: "icons/binary-code-binary-svgrepo-com.svg",
	},
	"GroupPolicyContainer": {
		Name: "Group Policy Container",
		Icon: "icons/gpo.svg",
	},
	"OrganizationalUnit": {
		Name: "Organizational Unit",
		Icon: "icons/source_black_24dp.svg",
	},
	"Container": {
		Name: "Container",
		Icon: "icons/folder_black_24dp.svg",
	},
	"CertificateTemplate": {
		Name: "Certificate Template",
		Icon: "icons/certificate.svg",
	},
	"DNSNode": {
		Name: "DNS Node",
		Icon: "icons/source_black_24dp.svg",
	},
	// "default", typeinfo{
	// 	Name: "Unknown",
	// 	Icon: "icons/help_black_24dp.svg",
	// },
}
