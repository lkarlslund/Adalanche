package activedirectory

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	PwnCreateUser                           = engine.NewPwn("CreateUser")
	PwnCreateGroup                          = engine.NewPwn("CreateGroup")
	PwnCreateComputer                       = engine.NewPwn("CreateComputer")
	PwnCreateAnyObject                      = engine.NewPwn("CreateAnyObject")
	PwnDeleteChildrenTarget                 = engine.NewPwn("DeleteChildrenTarget")
	PwnDeleteObject                         = engine.NewPwn("DeleteObject")
	PwnInheritsSecurity                     = engine.NewPwn("InheritsSecurity")
	PwnACLContainsDeny                      = engine.NewPwn("ACLContainsDeny").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return -1 })
	PwnResetPassword                        = engine.NewPwn("ResetPassword")
	PwnOwns                                 = engine.NewPwn("Owns")
	PwnGenericAll                           = engine.NewPwn("GenericAll")
	PwnWriteAll                             = engine.NewPwn("WriteAll")
	PwnWritePropertyAll                     = engine.NewPwn("WritePropertyAll")
	PwnWriteExtendedAll                     = engine.NewPwn("ExtendedAll")
	PwnTakeOwnership                        = engine.NewPwn("TakeOwnership")
	PwnWriteDACL                            = engine.NewPwn("WriteDACL")
	PwnWriteSPN                             = engine.NewPwn("WriteSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnWriteValidatedSPN                    = engine.NewPwn("WriteValidatedSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnWriteAllowedToAct                    = engine.NewPwn("WriteAllowedToAct")
	PwnAddMember                            = engine.NewPwn("AddMember")
	PwnAddMemberGroupAttr                   = engine.NewPwn("AddMemberGroupAttr")
	PwnAddSelfMember                        = engine.NewPwn("AddSelfMemeber")
	PwnReadMSAPassword                      = engine.NewPwn("ReadMSAPassword")
	PwnHasMSA                               = engine.NewPwn("HasMSA")
	PwnWriteKeyCredentialLink               = engine.NewPwn("WriteKeyCredentialLink")
	PwnWriteAttributeSecurityGUID           = engine.NewPwn("WriteAttributeSecurityGUID").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 5 }) // Only if you patch the DC, so this will actually never work
	PwnSIDHistoryEquality                   = engine.NewPwn("SIDHistoryEquality")
	PwnAllExtendedRights                    = engine.NewPwn("AllExtendedRights")
	PwnDSReplicationSyncronize              = engine.NewPwn("DSReplSync")
	PwnDSReplicationGetChanges              = engine.NewPwn("DSReplGetChngs")
	PwnDSReplicationGetChangesAll           = engine.NewPwn("DSReplGetChngsAll")
	PwnDSReplicationGetChangesInFilteredSet = engine.NewPwn("DSReplGetChngsInFilteredSet")
	PwnDCsync                               = engine.NewPwn("DCsync")
	PwnReadLAPSPassword                     = engine.NewPwn("ReadLAPSPassword")
	PwnMemberOfGroup                        = engine.NewPwn("MemberOfGroup")
	PwnHasSPN                               = engine.NewPwn("HasSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	})
	PwnHasSPNNoPreauth = engine.NewPwn("HasSPNNoPreauth").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	})
	PwnAdminSDHolderOverwriteACL  = engine.NewPwn("AdminSDHolderOverwriteACL")
	PwnComputerAffectedByGPO      = engine.NewPwn("ComputerAffectedByGPO")
	PwnGPOMachineConfigPartOfGPO  = engine.NewPwn("GPOMachineConfigPartOfGPO")
	PwnGPOUserConfigPartOfGPO     = engine.NewPwn("GPOUserConfigPartOfGPO")
	PwnLocalAdminRights           = engine.NewPwn("LocalAdminRights")
	PwnLocalRDPRights             = engine.NewPwn("LocalRDPRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnLocalDCOMRights            = engine.NewPwn("LocalDCOMRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 })
	PwnScheduledTaskOnUNCPath     = engine.NewPwn("ScheduledTaskOnUNCPath")
	PwnMachineScript              = engine.NewPwn("MachineScript")
	PwnWriteAltSecurityIdentities = engine.NewPwn("WriteAltSecurityIdentities")
	PwnWriteProfilePath           = engine.NewPwn("WriteProfilePath")
	PwnWriteScriptPath            = engine.NewPwn("WriteScriptPath")
	PwnCertificateEnroll          = engine.NewPwn("CertificateEnroll")
)
