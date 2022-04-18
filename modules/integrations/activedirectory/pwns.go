package activedirectory

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	PwnCreateUser           = engine.NewPwn("CreateUser").SetDefault(false, false, false)
	PwnCreateGroup          = engine.NewPwn("CreateGroup").SetDefault(false, false, false)
	PwnCreateComputer       = engine.NewPwn("CreateComputer").SetDefault(false, false, false)
	PwnCreateAnyObject      = engine.NewPwn("CreateAnyObject").SetDefault(false, false, false)
	PwnDeleteChildrenTarget = engine.NewPwn("DeleteChildrenTarget").SetDefault(false, false, false)
	PwnDeleteObject         = engine.NewPwn("DeleteObject").SetDefault(false, false, false)
	PwnInheritsSecurity     = engine.NewPwn("InheritsSecurity").SetDefault(false, false, false)
	PwnACLContainsDeny      = engine.NewPwn("ACLContainsDeny").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return -1 })
	PwnResetPassword        = engine.NewPwn("ResetPassword").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&engine.UAC_ACCOUNTDISABLE != 0 {
			return -1
		}
		return 100
	})
	PwnReadPasswordId = engine.NewPwn("ReadPasswordId").SetDefault(false, false, false).RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		return 5
	})
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
	PwnAddSelfMember                        = engine.NewPwn("AddSelfMember")
	PwnReadMSAPassword                      = engine.NewPwn("ReadMSAPassword")
	PwnHasMSA                               = engine.NewPwn("HasMSA")
	PwnWriteKeyCredentialLink               = engine.NewPwn("WriteKeyCredentialLink")
	PwnWriteAttributeSecurityGUID           = engine.NewPwn("WriteAttrSecurityGUID").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 5 }) // Only if you patch the DC, so this will actually never work
	PwnSIDHistoryEquality                   = engine.NewPwn("SIDHistoryEquality")
	PwnAllExtendedRights                    = engine.NewPwn("AllExtendedRights")
	PwnDSReplicationSyncronize              = engine.NewPwn("DSReplSync")
	PwnDSReplicationGetChanges              = engine.NewPwn("DSReplGetChngs")
	PwnDSReplicationGetChangesAll           = engine.NewPwn("DSReplGetChngsAll")
	PwnDSReplicationGetChangesInFilteredSet = engine.NewPwn("DSReplGetChngsInFiltSet")
	PwnDCsync                               = engine.NewPwn("DCsync")
	PwnReadLAPSPassword                     = engine.NewPwn("ReadLAPSPassword")
	PwnMemberOfGroup                        = engine.NewPwn("MemberOfGroup")
	PwnHasSPN                               = engine.NewPwn("HasSPN").Describe("Kerberoastable by requesting Kerberos service ticket against SPN and then bruteforcing the ticket").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	})
	PwnDontReqPreauth = engine.NewPwn("DontReqPreauth").Describe("Kerberoastable by AS-REP by requesting a TGT and then bruteforcing the ticket").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	})
	PwnOverwritesACL              = engine.NewPwn("OverwritesACL")
	PwnAffectedByGPO              = engine.NewPwn("AffectedByGPO")
	PartOfGPO                     = engine.NewPwn("PartOfGPO")
	PwnLocalAdminRights           = engine.NewPwn("AdminRights")
	PwnLocalRDPRights             = engine.NewPwn("RDPRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnLocalDCOMRights            = engine.NewPwn("DCOMRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 })
	PwnScheduledTaskOnUNCPath     = engine.NewPwn("SchedTaskOnUNCPath")
	PwnMachineScript              = engine.NewPwn("MachineScript")
	PwnWriteAltSecurityIdentities = engine.NewPwn("WriteAltSecIdent")
	PwnWriteProfilePath           = engine.NewPwn("WriteProfilePath")
	PwnWriteScriptPath            = engine.NewPwn("WriteScriptPath")
	PwnCertificateEnroll          = engine.NewPwn("CertificateEnroll")
)
