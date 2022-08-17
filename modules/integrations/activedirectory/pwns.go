package activedirectory

import "github.com/lkarlslund/adalanche/modules/engine"

var (
	PwnACLContainsDeny = engine.NewEdge("ACLContainsDeny").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return -1 })
	PwnResetPassword   = engine.NewEdge("ResetPassword").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&engine.UAC_ACCOUNTDISABLE != 0 {
			return -1
		}
		return 100
	})
	PwnReadPasswordId = engine.NewEdge("ReadPasswordId").SetDefault(false, false, false).RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		return 5
	})
	PwnOwns             = engine.NewEdge("Owns")
	PwnGenericAll       = engine.NewEdge("GenericAll")
	PwnWriteAll         = engine.NewEdge("WriteAll")
	PwnWritePropertyAll = engine.NewEdge("WritePropertyAll")
	PwnWriteExtendedAll = engine.NewEdge("ExtendedAll")
	PwnTakeOwnership    = engine.NewEdge("TakeOwnership")
	PwnWriteDACL        = engine.NewEdge("WriteDACL")
	PwnWriteSPN         = engine.NewEdge("WriteSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	})
	PwnWriteValidatedSPN = engine.NewEdge("WriteValidatedSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	})
	PwnWriteAllowedToAct                    = engine.NewEdge("WriteAllowedToAct")
	PwnAddMember                            = engine.NewEdge("AddMember")
	PwnAddMemberGroupAttr                   = engine.NewEdge("AddMemberGroupAttr")
	PwnAddSelfMember                        = engine.NewEdge("AddSelfMember")
	PwnReadMSAPassword                      = engine.NewEdge("ReadMSAPassword")
	PwnHasMSA                               = engine.NewEdge("HasMSA")
	PwnWriteKeyCredentialLink               = engine.NewEdge("WriteKeyCredentialLink")
	PwnWriteAttributeSecurityGUID           = engine.NewEdge("WriteAttrSecurityGUID").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 5 }) // Only if you patch the DC, so this will actually never work
	PwnSIDHistoryEquality                   = engine.NewEdge("SIDHistoryEquality")
	PwnAllExtendedRights                    = engine.NewEdge("AllExtendedRights")
	PwnDSReplicationSyncronize              = engine.NewEdge("DSReplSync")
	PwnDSReplicationGetChanges              = engine.NewEdge("DSReplGetChngs")
	PwnDSReplicationGetChangesAll           = engine.NewEdge("DSReplGetChngsAll")
	PwnDSReplicationGetChangesInFilteredSet = engine.NewEdge("DSReplGetChngsInFiltSet")
	PwnDCsync                               = engine.NewEdge("DCsync")
	PwnReadLAPSPassword                     = engine.NewEdge("ReadLAPSPassword")
	PwnMemberOfGroup                        = engine.NewEdge("MemberOfGroup")
	PwnHasSPN                               = engine.NewEdge("HasSPN").Describe("Kerberoastable by requesting Kerberos service ticket against SPN and then bruteforcing the ticket").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	})
	PwnDontReqPreauth = engine.NewEdge("DontReqPreauth").Describe("Kerberoastable by AS-REP by requesting a TGT and then bruteforcing the ticket").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	})
	PwnOverwritesACL              = engine.NewEdge("OverwritesACL")
	PwnAffectedByGPO              = engine.NewEdge("AffectedByGPO")
	PartOfGPO                     = engine.NewEdge("PartOfGPO")
	PwnLocalAdminRights           = engine.NewEdge("AdminRights")
	PwnLocalRDPRights             = engine.NewEdge("RDPRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnLocalDCOMRights            = engine.NewEdge("DCOMRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 })
	PwnScheduledTaskOnUNCPath     = engine.NewEdge("SchedTaskOnUNCPath")
	PwnMachineScript              = engine.NewEdge("MachineScript")
	PwnWriteAltSecurityIdentities = engine.NewEdge("WriteAltSecIdent")
	PwnWriteProfilePath           = engine.NewEdge("WriteProfilePath")
	PwnWriteScriptPath            = engine.NewEdge("WriteScriptPath")
	PwnCertificateEnroll          = engine.NewEdge("CertificateEnroll")
)
