package aql

var (
	PredefinedQueries = []QueryDefinition{
		{
			Name:    "Who owns your AD? (Reach Domain Admin etc)",
			Query:   "ACYCLIC (start:&(dataLoader=Active Directory)(type=Group)(|(objectSid=S-1-5-32-544)(objectSid=S-1-5-21-*-512)(objectSid=S-1-5-21-*-519)))<-[]{1,10}-(end:type=Person)",
			Default: true,
		},
		{
			Name:  "Who can DCsync?",
			Query: "ACYCLIC (start:&(name=DCsync)(type=Callable-Service-Point))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "How to reach machines that have computer accounts with unconstrained delegation (non-DCs)",
			Query: "ACYCLIC (start:tag=unconstrained)<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "What can accounts with no Kerberos preauth requirement reach? (ASREPROAST)",
			Query: "ACYCLIC (start:&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(tag=account_active))-[]{1,10}->(end:)",
		},
		{
			Name:  "Who can pwn your AD by sideloading a custom DLL on your DC? (Old DCs only)",
			Query: "ACYCLIC (start:distinguishedname=CN=MicrosoftDNS,CN=System,DC=*)<-[]{1,15}-(end:type=Person)",
		},
		{
			Name:  "Who can dump SAM/SYSTEM or your ntds.dit remotely or via RDP? (Server and Backup Operators)",
			Query: "ACYCLIC (start:&(dataLoader=Active Directory)(|(objectSid=S-1-5-32-551)(objectSid=S-1-5-32-549)))<-[]{1,10}-(end:)",
		},
		{
			Name:  "Enroll in ESC1 vulnerable certificate templates (client auth + pose as anyone)",
			Query: "ACYCLIC (start:&(type=PKI-Certificate-Template)(msPKI-Certificate-Name-Flag:and:=1)(|(pKIExtendedKeyUsage=1.3.6.1.5.5.7.3.2)(pKIExtendedKeyUsage=1.3.5.1.5.2.3.4)(pKIExtendedKeyUsage=1.3.6.1.4.1.311.20.2.2)(pKIExtendedKeyUsage=2.5.29.37.0)(pKIExtendedKeyUsage:count:=0)))<-[CertificateEnroll]-()-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "Enroll in ESC15 vulnerable certificate templates (v1 + pose as anyone)",
			Query: "ACYCLIC (start:&(type=PKI-Certificate-Template)(msPKI-Certificate-Name-Flag:and:=1)(msPKI-Template-Schema-Version=1))<-[CertificateEnroll]-()-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "What can Domain Users, Authenticated Users and Everyone do?",
			Query: "ACYCLIC (start:&(dataLoader=Active Directory)(|(objectSid=S-1-5-21-*-513)(objectSid=S-1-5-11)(objectSid=S-1-1-0)))-[]{1,10}->(end:)",
		},
		{
			Name:  "Who can dump a virtual DC? (hypervisor/SAN sounding groups)",
			Query: "ACYCLIC (start:&(dataLoader=Active Directory)(type=Group)(|(name=*vcenter*)(name=*vmware*)(name=*esxi*)(name=*vsan*)(name=*simplivity*)))<-[]{1,10}-(end:)",
		},
		{
			Name:  "Who can wipe or access your backups? (backup sounding groups)",
			Query: "ACYCLIC (start:&(dataLoader=Active Directory)(type=Group)(|(name=*backup*)(name=*veeam*)(name=*tsm*)(name=*tivoli storage*)(name=*rubrik*)(name=*commvault*)))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "Who can change GPOs?",
			Query: "ACYCLIC (start:&(dataLoader=Active Directory)(type=Group-Policy-Container))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "What can users not required to have a password reach?",
			Query: "ACYCLIC (start:&(dataLoader=Active Directory)(type=Person)(userAccountControl:1.2.840.113556.1.4.803:=32))-[]{1,10}->(end:)",
		},
		{
			Name:  "What can users that can't change password reach?",
			Query: "ACYCLIC (start:&(type=Person)(userAccountControl:1.2.840.113556.1.4.803:=64))-[]{1,10}->(end:)",
		},
		{
			Name:  "What can users with never expiring passwords reach?",
			Query: "ACYCLIC (start:&(type=Person)(userAccountControl:1.2.840.113556.1.4.803:=65536))-[]{1,10}->(end:)",
		},
		{
			Name:  "What can accounts that have a password older than 5 years reach?",
			Query: "ACYCLIC (start:&(objectClass=Person)(!(pwdLastSet=0))(pwdLastSet:since:<-5Y)(!(userAccountControl:and:=2)))-[]{1,10}->(end:)",
		},
		{
			Name:  "What can accounts that have never set a password reach?",
			Query: "ACYCLIC (start:&(dataLoader=Active Directory)(objectClass=Person)(pwdLastSet=0)(|(logonCount=0)(!(logonCount=*)))(!(userAccountControl:and:=2)))-[]{1,10}->(end:)",
		},
		{
			Name:  "Who can control Protected Users?",
			Query: "ACYCLIC (start:&(type=Group)(distinguishedName=CN=Protected Users,*))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "What can kerberoastable user accounts reach?",
			Query: "ACYCLIC (start:&(type=Person)(servicePrincipalName=*)(tag=account_active))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "What can large groups (more than 100 members) reach?",
			Query: "ACYCLIC (start:&(type=Group)(member:count:>100))-[]{1,10}->(end:)",
		},
		{
			Name:  "Who can reach Domain Controllers?",
			Query: "ACYCLIC (start:&(type=Machine)(out=MachineAccount,(&(type=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "Who can reach Read-Only Domain Controllers? (RODC)",
			Query: "ACYCLIC (start:&(type=Machine)(out=MachineAccount,(&(type=Computer)(primaryGroupId=521))))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "Who can reach computers with unconstrained delegation (non DCs)?",
			Query: "ACYCLIC (start:&(type=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!userAccountControl:1.2.840.113556.1.4.803:=8192))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "Who can reach computers with constrained delegation (non DCs)?",
			Query: "ACYCLIC (start:&(objectCategory=computer)(msds-allowedtodelegateto=*)(!userAccountControl:1.2.840.113556.1.4.803:=8192))<-[]{1,10}-(end:type=Person)",
		},
		{
			Name:  "Users that are members of more than 25 groups",
			Query: "ACYCLIC (start:&(type=Person)(memberOf:count:>10))",
		},
		{
			Name:  "Give me 100 random machines",
			Query: "ACYCLIC (start:&(type=Machine)(out=MachineAccount,(userAccountControl:1.2.840.113556.1.4.803:=4096)) LIMIT 100)",
		},
	}
)
