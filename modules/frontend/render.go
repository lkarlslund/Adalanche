package frontend

type typeinfo struct {
	Name            string `json:"name"`
	Icon            string `json:"icon"`
	BackgroundColor string `json:"background-color"`
}

var typeInfos = map[string]typeinfo{
	"Person": {
		Name: "Person",
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
	"ms-DS-Managed-Service-Account": {
		Name: "Managed Service Account",
		Icon: "icons/manage_accounts_black_24dp.svg",
	},
	"ms-DS-Group-Managed-Service-Account": {
		Name: "Group Managed Service Account",
		Icon: "icons/manage_accounts_black_24dp.svg",
	},
	"Foreign-Security-Principal": {
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
	"Group-Policy-Container": {
		Name: "Group Policy Container",
		Icon: "icons/gpo.svg",
	},
	"Organizational-Unit": {
		Name: "Organizational Unit",
		Icon: "icons/source_black_24dp.svg",
	},
	"Container": {
		Name: "Container",
		Icon: "icons/folder_black_24dp.svg",
	},
	"MS-PKI-Certificate-Template": {
		Name: "Certificate Template",
		Icon: "icons/certificate.svg",
	},
	"DNS-Node": {
		Name: "DNS Node",
		Icon: "icons/source_black_24dp.svg",
	},
	// "default", typeinfo{
	// 	Name: "Unknown",
	// 	Icon: "icons/help_black_24dp.svg",
	// },
}
