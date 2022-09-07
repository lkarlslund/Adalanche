package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var (
	LocalMachineSID         = engine.NewAttribute("localMachineSID")
	LocalMachineSIDOriginal = engine.NewAttribute("localMachineSIDOriginal")
	AbsolutePath            = engine.NewAttribute("absolutePath")
	ShareType               = engine.NewAttribute("shareType")
	ServiceStart            = engine.NewAttribute("serviceStart")
	ServiceType             = engine.NewAttribute("serviceType")

	PwnLocalAdminRights             = engine.NewEdge("AdminRights")
	PwnLocalRDPRights               = engine.NewEdge("RDPRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnLocalDCOMRights              = engine.NewEdge("DCOMRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 })
	PwnLocalSMSAdmins               = engine.NewEdge("SMSAdmins").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 })
	PwnLocalSessionLastDay          = engine.NewEdge("SessionLastDay").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 80 })
	PwnLocalSessionLastWeek         = engine.NewEdge("SessionLastWeek").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 55 })
	PwnLocalSessionLastMonth        = engine.NewEdge("SessionLastMonth").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnHasServiceAccountCredentials = engine.NewEdge("SvcAccntCreds")
	PwnHasAutoAdminLogonCredentials = engine.NewEdge("AutoAdminLogonCreds")
	PwnRunsExecutable               = engine.NewEdge("RunsExecutable")
	PwnHosts                        = engine.NewEdge("Hosts")
	PwnRunsAs                       = engine.NewEdge("RunsAs")
	PwnExecuted                     = engine.NewEdge("Executed")
	PwnFileOwner                    = engine.NewEdge("FileOwner")
	PwnFileTakeOwnership            = engine.NewEdge("FileTakeOwnership")
	PwnFileWrite                    = engine.NewEdge("FileWrite")
	PwnFileRead                     = engine.NewEdge("FileRead")
	PwnFileModifyDACL               = engine.NewEdge("FileModifyDACL")
	PwnFileShare                    = engine.NewEdge("FileShare")
	PwnRegistryOwns                 = engine.NewEdge("RegistryOwns")
	PwnRegistryWrite                = engine.NewEdge("RegistryWrite")
	PwnRegistryModifyDACL           = engine.NewEdge("RegistryModifyDACL")
	PwnRegistryModifyOwner          = engine.NewEdge("RegistryModifyOwner")

	PwnSeBackupPrivilege        = engine.NewEdge("SeBackupPrivilege")
	PwnSeRestorePrivilege       = engine.NewEdge("SeRestorePrivilege")
	PwnSeTakeOwnershipPrivilege = engine.NewEdge("SeTakeOwnershipPrivilege")

	PwnSeAssignPrimaryToken = engine.NewEdge("SeAssignPrimaryToken")
	PwnSeCreateToken        = engine.NewEdge("SeCreateToken")
	PwnSeDebug              = engine.NewEdge("SeDebug")
	PwnSeImpersonate        = engine.NewEdge("SeImpersonate").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 20 })
	PwnSeLoadDriver         = engine.NewEdge("SeLoadDriver")
	PwnSeManageVolume       = engine.NewEdge("SeManageVolume")
	PwnSeTakeOwnership      = engine.NewEdge("SeTakeOwnership")
	PwnSeTcb                = engine.NewEdge("SeTcb")

	PwnSIDCollision = engine.NewEdge("SIDCollision")

	DNSHostname        = engine.NewAttribute("dnsHostName")
	PwnControlsUpdates = engine.NewEdge("ControlsUpdates")
	WUServer           = engine.NewAttribute("wuServer")
	SCCMServer         = engine.NewAttribute("sccmServer")
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
