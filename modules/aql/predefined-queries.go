package aql

var (
	PredefinedQueries = []QueryDefinition{
		{
			Name:        "High Value Targets",
			Query:       "ACYCLIC start:(tag=hvt)<-[()]{1,6}-end:(&(dataLoader=Active Directory)(|(&(tag=account_enabled)(type=Person))(type=Group)))",
			Description: "High value targets in the network, that will compromise the entire AD if they're reached. This is the query to rule them all.",
			Default:     true,
		},
		{
			Name:        "Reach Domain Admin, Administrators and Enterprise Admins",
			Query:       "ACYCLIC start:(&(dataLoader=Active Directory)(type=Group)(|(objectSid=S-1-5-32-544)(objectSid=S-1-5-21-*-512)(objectSid=S-1-5-21-*-519)))<-[()]{1,6}-end:(|(type=Person)(type=Group))",
			Description: "Find all the paths to reach Domain Admins, Administrators and Enterprise Admins.",
			Category:    "Active Directory",
		},
		{
			Name:        "Run DCsync",
			Query:       "ACYCLIC start:(&(name=DCsync)(type=Callable-Service-Point))<-[()]{1,6}-end:(|(type=Person)(type=Group))",
			Description: "Find all the paths to run DCsync, enabling the attacker to dump all the hashes from the domain.",
			Category:    "Active Directory",
		},
		{
			Name:        "Unconstrained Delegation",
			Query:       "ACYCLIC start:(tag=unconstrained)<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Description: "How to reach machines that have computer accounts with unconstrained delegation (non-DCs)",
		},
		{
			Name:     "What can accounts with no Kerberos preauth requirement reach? (ASREPROAST)",
			Query:    "ACYCLIC start:(&(samAccountType=805306368)(userAccountControl:and:=4194304)(tag=account_active))-[]{1,6}->end:()",
			Category: "Active Directory",
		},
		{
			Name:     "Who can pwn your AD by sideloading a custom DLL on your DC? (Old DCs only)",
			Query:    "ACYCLIC start:(distinguishedname=CN=MicrosoftDNS,CN=System,DC=*)<-[]{1,15}-end:(|(type=Person)(type=Group))",
			Category: "Active Directory",
		},
		{
			Name:     "Who can dump SAM/SYSTEM or your ntds.dit remotely or via RDP? (Server and Backup Operators)",
			Query:    "ACYCLIC start:(&(dataLoader=Active Directory)(|(objectSid=S-1-5-32-551)(objectSid=S-1-5-32-549)))<-[]{1,6}-end:()",
			Category: "Active Directory",
		},
		{
			Name:     "Enroll in ESC1 vulnerable certificate templates (client auth + pose as anyone)",
			Query:    "ACYCLIC start:(&(type=PKI-Certificate-Template)(msPKI-Certificate-Name-Flag:and:=1)(|(pKIExtendedKeyUsage=1.3.6.1.5.5.7.3.2)(pKIExtendedKeyUsage=1.3.5.1.5.2.3.4)(pKIExtendedKeyUsage=1.3.6.1.4.1.311.20.2.2)(pKIExtendedKeyUsage=2.5.29.37.0)(pKIExtendedKeyUsage:count:=0)))<-[CertificateEnroll]-()<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Category: "Certificate Services",
		},
		{
			Name:     "Enroll in ESC15 vulnerable certificate templates (v1 + pose as anyone)",
			Query:    "ACYCLIC start:(&(type=PKI-Certificate-Template)(msPKI-Certificate-Name-Flag:and:=1)(msPKI-Template-Schema-Version=1))<-[CertificateEnroll]-()<-[]{0,10}-end:(|(type=Person)(type=Group))",
			Category: "Certificate Services",
		},
		{
			Name:     "What can Domain Users, Authenticated Users and Everyone do?",
			Query:    "ACYCLIC start:(&(dataLoader=Active Directory)(|(objectSid=S-1-5-21-*-513)(objectSid=S-1-5-11)(objectSid=S-1-1-0)))-[]{1,6}->end:()",
			Category: "Active Directory",
		},
		{
			Name:     "Who can dump a virtual DC? (hypervisor/SAN sounding groups)",
			Query:    "ACYCLIC start:(&(dataLoader=Active Directory)(type=Group)(|(name=*vcenter*)(name=*vmware*)(name=*esxi*)(name=*vsan*)(name=*simplivity*)))<-[]{1,6}-end:()",
			Category: "Active Directory",
		},
		{
			Name:     "Who can wipe or access your backups? (backup sounding groups)",
			Query:    "ACYCLIC start:(&(dataLoader=Active Directory)(type=Group)(|(name=*backup*)(name=*veeam*)(name=*tsm*)(name=*tivoli storage*)(name=*rubrik*)(name=*commvault*)))<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Category: "Active Directory",
		},
		{
			Name:     "Who can change GPOs?",
			Query:    "ACYCLIC start:(&(dataLoader=Active Directory)(type=Group-Policy-Container))<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Category: "Active Directory",
		},
		{
			Name:     "What can users not required to have a password reach?",
			Query:    "ACYCLIC start:(&(dataLoader=Active Directory)(type=Person)(userAccountControl:and:=32))-[]{1,6}->end:()",
			Category: "Active Directory",
		},
		{
			Name:     "What can users that can't change password reach?",
			Query:    "ACYCLIC start:(&(type=Person)(userAccountControl:and:=64))-[]{1,6}->end:()",
			Category: "Active Directory",
		},
		{
			Name:     "What can users with never expiring passwords reach?",
			Query:    "ACYCLIC start:(&(type=Person)(userAccountControl:and:=65536))-[]{1,6}->end:()",
			Category: "Active Directory",
		},
		{
			Name:     "What can accounts that have a password older than 5 years reach?",
			Query:    "ACYCLIC start:(&(objectClass=Person)(!(pwdLastSet=0))(pwdLastSet:since:<-5Y)(!(userAccountControl:and:=2)))-[]{1,6}->end:()",
			Category: "Active Directory",
		},
		{
			Name:     "What can accounts that have never set a password reach?",
			Query:    "ACYCLIC start:(&(dataLoader=Active Directory)(objectClass=Person)(pwdLastSet=0)(|(logonCount=0)(!(logonCount=*)))(!(userAccountControl:and:=2)))-[]{1,6}->end:()",
			Category: "Active Directory",
		},
		{
			Name:        "Protected Users",
			Query:       "ACYCLIC start:(&(type=Group)(distinguishedName=CN=Protected Users,*))<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Description: "Who can tamper with the Protected Users group?",
			Category:    "Active Directory",
		},
		{
			Name:     "What can kerberoastable user accounts reach? (all encryption types)",
			Query:    "ACYCLIC start:(&(type=Person)(servicePrincipalName=*)(tag=account_active))-[]{1,6}->end:(|(type=Person)(type=Group))",
			Category: "Roasting",
		},
		{
			Name:     "What can kerberoastable user accounts reach? (RC4 encryption)",
			Query:    "ACYCLIC start:(&(type=Person)(servicePrincipalName=*)(|(msDS-SupportedEncryptionTypes:and:=0x4)(!msDS-SupportedEncryptionTypes=*))(tag=account_active))-[]{1,6}->end:(|(type=Person)(type=Group))",
			Category: "Roasting",
		},
		{
			Name:        "Large groups",
			Query:       "ACYCLIC start:(&(type=Group)(member:count:>100))-[]{1,6}->end:()",
			Description: "What can large groups (more than 100 members) reach?",
			Category:    "Examples",
		},
		{
			Name:        "Domain Controllers",
			Query:       "ACYCLIC start:(&(type=Machine)(out=MachineAccount,(&(type=Computer)(userAccountControl:and:=8192))))<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Description: "Domain Controllers are critical servers in Active Directory environments. They authenticate users and services within the domain. Compromising these machines allows attackers to take over the entire AD.",
			Category:    "Active Directory",
		},
		{
			Name:        "Who can reach Read-Only Domain Controllers (RODC)",
			Query:       "ACYCLIC start:(&(type=Machine)(out=MachineAccount,(&(type=Computer)(primaryGroupId=521))))<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Description: "Read-Only Domain Controllers (RODC) are used to reduce the risk of password replication. They only replicate a subset of the domain's data and are typically located in remote offices. Compromising RODCs can lead to unauthorized access to sensitive information, depending on how they're configured for caching credentials.",
			Category:    "Active Directory",
		},
		{
			Name:     "Computers with unconstrained delegation (non DCs)?",
			Query:    "ACYCLIC start:(&(type=Computer)(userAccountControl:and:=524288)(!userAccountControl:and:=8192))<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Category: "Active Directory",
		},
		{
			Name:     "Computers with constrained delegation (non DCs)",
			Query:    "ACYCLIC start:(&(objectCategory=computer)(msds-allowedtodelegateto=*)(!userAccountControl:and:=8192))<-[]{1,6}-end:(|(type=Person)(type=Group))",
			Category: "Active Directory",
		},
		{
			Name:     "Users that are members of more than 25 groups",
			Query:    "ACYCLIC start:(&(type=Person)(memberOf:count:>10))",
			Category: "Examples",
		},
		{
			Name:     "100 random machines",
			Query:    "ACYCLIC start:(&(type=Machine)(out=MachineAccount,(userAccountControl:and:=4096))) LIMIT 100",
			Category: "Examples",
		},
	}
)
