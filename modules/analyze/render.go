package analyze

type typeinfo struct {
	Name string
	Icon string
}

var typeInfos = map[string]typeinfo{
	"User": typeinfo{
		Name: "User",
		Icon: "icons/person-fill.svg",
	},
	"Group": typeinfo{
		Name: "Group",
		Icon: "icons/people-fill.svg",
	},
	"Computer": typeinfo{
		Name: "Computer",
		Icon: "icons/computer-fill.svg",
	},
	"Machine": typeinfo{
		Name: "Machine",
		Icon: "icons/tv-fill.svg",
	},
	"ManagedServiceAccount": typeinfo{
		Name: "Managed Service Account",
		Icon: "icons/manage_accounts_black_24dp.svg",
	},
	"GroupManagedServiceAccount": typeinfo{
		Name: "Group Managed Service Account",
		Icon: "icons/manage_accounts_black_24dp.svg",
	},
	"ForeignSecurityPrincipal": typeinfo{
		Name: "Foreign Security Principal",
		Icon: "icons/badge_black_24dp.svg",
	},
	"Service": typeinfo{
		Name: "Service",
		Icon: "icons/service.svg",
	},
	"Directory": typeinfo{
		Name: "Directory",
		Icon: "icons/source_black_24dp.svg",
	},
	"File": typeinfo{
		Name: "File",
		Icon: "icons/source_black_24dp.svg",
	},
	"Executable": typeinfo{
		Name: "Executable",
		Icon: "icons/binary-code-binary-svgrepo-com.svg",
	},
	"GroupPolicyContainer": typeinfo{
		Name: "Group Policy Container",
		Icon: "icons/gpo.svg",
	},
	"OrganizationalUnit": typeinfo{
		Name: "Organizational Unit",
		Icon: "icons/source_black_24dp.svg",
	},
	"Container": typeinfo{
		Name: "Container",
		Icon: "icons/folder_black_24dp.svg",
	},
	"CertificateTemplate": typeinfo{
		Name: "Certificate Template",
		Icon: "icons/certificate.svg",
	},
	"DNSNode": typeinfo{
		Name: "DNS Node",
		Icon: "icons/source_black_24dp.svg",
	},
	// "default", typeinfo{
	// 	Name: "Unknown",
	// 	Icon: "icons/help_black_24dp.svg",
	// },
}
