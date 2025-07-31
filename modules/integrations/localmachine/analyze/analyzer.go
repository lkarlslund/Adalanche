package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var (
	LocalMachineSID         = engine.NewAttribute("localMachineSID")
	LocalMachineSIDOriginal = engine.NewAttribute("localMachineSIDOriginal")
	AbsolutePath            = engine.NewAttribute("absolutePath")
	ShareType               = engine.NewAttribute("shareType")
	ServiceStart            = engine.NewAttribute("serviceStart")
	ServiceType             = engine.NewAttribute("serviceType")

	EdgeLocalAdminRights = engine.NewEdge("AdminRights").Tag("Granted")
	EdgeLocalRDPRights   = engine.NewEdge("RDPRights").RegisterProbabilityCalculator(activedirectory.FixedProbability(30)).Tag("Granted").Tag("Pivot")
	EdgeLocalDCOMRights  = engine.NewEdge("DCOMRights").RegisterProbabilityCalculator(activedirectory.FixedProbability(30)).Tag("Granted")
	EdgeLocalSMSAdmins   = engine.NewEdge("SMSAdmins").RegisterProbabilityCalculator(activedirectory.FixedProbability(50)).Tag("Granted")

	EdgeSession                 = engine.NewEdge("Session").RegisterProbabilityCalculator(activedirectory.FixedProbability(80)).Tag("Pivot").Describe("Account has some sort of session on this machine")
	EdgeSessionLocal            = engine.NewEdge("SessionLocal").RegisterProbabilityCalculator(activedirectory.FixedProbability(55)).Tag("Pivot")
	EdgeSessionRDP              = engine.NewEdge("SessionRDP").RegisterProbabilityCalculator(activedirectory.FixedProbability(30)).Tag("Pivot")
	EdgeSessionService          = engine.NewEdge("SessionService").RegisterProbabilityCalculator(activedirectory.FixedProbability(30)).Tag("Pivot").Describe("Account detected as running a service on machine")
	EdgeSessionBatch            = engine.NewEdge("SessionBatch").RegisterProbabilityCalculator(activedirectory.FixedProbability(30)).Tag("Pivot").Describe("Account detected as being used in a scheduled task on machine")
	EdgeSessionNetwork          = engine.NewEdge("SessionNetwork").RegisterProbabilityCalculator(activedirectory.FixedProbability(30)).Tag("Pivot").Describe("Account detected as connecting to machine over the network")
	EdgeSessionNetworkNTLM      = engine.NewEdge("SessionNetworkNTLM").RegisterProbabilityCalculator(activedirectory.FixedProbability(30)).Tag("Pivot").Describe("Account detected as connecting to machine over the network using NTLM")
	EdgeSessionNetworkNTLMv2    = engine.NewEdge("SessionNetworkNTLMV2").RegisterProbabilityCalculator(activedirectory.FixedProbability(20)).Tag("Pivot").Describe("Account detected as connecting to machine over the network using NTLM V2")
	EdgeSessionNetworkKerberos  = engine.NewEdge("SessionNetworkKerberos").RegisterProbabilityCalculator(activedirectory.FixedProbability(20)).Tag("Pivot").Describe("Account detected as connecting to machine over the network using Kerberos")
	EdgeSessionNetworkNegotiate = engine.NewEdge("SessionNetworkNegotiate").RegisterProbabilityCalculator(activedirectory.FixedProbability(20)).Tag("Pivot").Describe("Account detected as connecting to machine over the network using Negotiate")
	EdgeSessionNetworkPlaintext = engine.NewEdge("SessionNetworkPlaintext").RegisterProbabilityCalculator(activedirectory.FixedProbability(80)).Tag("Pivot").Describe("Account detected as connecting to machine over the network using plaintext credentials")

	EdgeHasServiceAccountCredentials = engine.NewEdge("SvcAccntCreds").Tag("Pivot")
	EdgeHasAutoAdminLogonCredentials = engine.NewEdge("AutoAdminLogonCreds").Tag("Pivot")
	EdgeRunsExecutable               = engine.NewEdge("RunsExecutable")
	EdgeHosts                        = engine.NewEdge("Hosts")
	EdgeExecuted                     = engine.NewEdge("Executed")
	EdgeMemberOfGroup                = engine.NewEdge("MemberOfGroup")
	EdgeFileWrite                    = engine.NewEdge("FileWrite")
	EdgeFileRead                     = engine.NewEdge("FileRead")
	EdgeShares                       = engine.NewEdge("Shares").Describe("Machine offers a file share")
	EdgeRegistryOwns                 = engine.NewEdge("RegistryOwns")
	EdgeRegistryWrite                = engine.NewEdge("RegistryWrite")
	EdgeRegistryModifyDACL           = engine.NewEdge("RegistryModifyDACL")
	EdgeRegistryModifyOwner          = engine.NewEdge("RegistryModifyOwner")

	EdgeSeBackupPrivilege        = engine.NewEdge("SeBackupPrivilege")
	EdgeSeRestorePrivilege       = engine.NewEdge("SeRestorePrivilege")
	EdgeSeTakeOwnershipPrivilege = engine.NewEdge("SeTakeOwnershipPrivilege")

	EdgeSeAssignPrimaryToken   = engine.NewEdge("SeAssignPrimaryToken").Tag("Pivot")
	EdgeSeCreateToken          = engine.NewEdge("SeCreateToken").Tag("Pivot")
	EdgeSeDebug                = engine.NewEdge("SeDebug").Tag("Pivot")
	EdgeSeImpersonate          = engine.NewEdge("SeImpersonate").RegisterProbabilityCalculator(activedirectory.FixedProbability(20)).Tag("Pivot")
	EdgeSeLoadDriver           = engine.NewEdge("SeLoadDriver").Tag("Pivot")
	EdgeSeManageVolume         = engine.NewEdge("SeManageVolume").Tag("Pivot")
	EdgeSeTakeOwnership        = engine.NewEdge("SeTakeOwnership").Tag("Pivot")
	EdgeSeTrustedCredManAccess = engine.NewEdge("SeTrustedCredManAccess").Tag("Pivot")
	EdgeSeTcb                  = engine.NewEdge("SeTcb").Tag("Pivot")

	EdgeSeNetworkLogonRight = engine.NewEdge("SeNetworkLogonRight").RegisterProbabilityCalculator(activedirectory.FixedProbability(10))
	// RDPRight used ... EdgeSeRemoteInteractiveLogonRight = engine.NewEdge("SeRemoteInteractiveLogonRight").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 10 })

	// SeDenyNetworkLogonRight
	// SeDenyInteractiveLogonRight
	// SeDenyRemoteInteractiveLogonRight

	EdgeSIDCollision = engine.NewEdge("SIDCollision").Tag("Informative").RegisterProbabilityCalculator(activedirectory.FixedProbability(0))

	DNSHostname         = engine.NewAttribute("dnsHostName")
	EdgeControlsUpdates = engine.NewEdge("ControlsUpdates").Tag("Affects")
	WUServer            = engine.NewAttribute("wuServer")
	SCCMServer          = engine.NewAttribute("sccmServer")

	EdgePublishes = engine.NewEdge("Publishes").Tag("Informative")

	ObjectTypeShare = engine.NewObjectType("Share", "Share")
)

func MapSID(original, new, input windowssecurity.SID) windowssecurity.SID {
	// If input SID is one longer than machine sid
	if input.Components() == original.Components()+1 {
		// And it matches the original SID
		if input.StripRID() == original {
			// Return mapped SID
			return new.AddComponent(input.RID())
		}
	}
	// No mapping
	return input
}
