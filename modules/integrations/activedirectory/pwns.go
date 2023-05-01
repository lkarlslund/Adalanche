package activedirectory

import "github.com/lkarlslund/adalanche/modules/engine"

func NotAChance(source, target *engine.Object) engine.Probability {
	return 0
}

var (
	EdgeACLContainsDeny = engine.NewEdge("ACLContainsDeny").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return -1 }).Tag("Informative")
	EdgeResetPassword   = engine.NewEdge("ResetPassword").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&engine.UAC_ACCOUNTDISABLE != 0 {
			return -1
		}
		return 100
	}).Tag("Escalation")
	EdgeReadPasswordId = engine.NewEdge("ReadPasswordId").SetDefault(false, false, false).RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		return 5
	})
	EdgeOwns             = engine.NewEdge("Owns").Tag("Escalation")
	EdgeGenericAll       = engine.NewEdge("GenericAll").Tag("Informative")
	EdgeWriteAll         = engine.NewEdge("WriteAll").Tag("Informative").RegisterProbabilityCalculator(NotAChance)
	EdgeWritePropertyAll = engine.NewEdge("WritePropertyAll").Tag("Informative").RegisterProbabilityCalculator(NotAChance)
	EdgeWriteExtendedAll = engine.NewEdge("WriteExtendedAll").Tag("Informative").RegisterProbabilityCalculator(NotAChance)
	EdgeTakeOwnership    = engine.NewEdge("TakeOwnership").Tag("Escalation")
	EdgeWriteDACL        = engine.NewEdge("WriteDACL").Tag("Escalation")
	EdgeWriteSPN         = engine.NewEdge("WriteSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	}).Tag("Escalation")
	EdgeWriteValidatedSPN = engine.NewEdge("WriteValidatedSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	}).Tag("Escalation")
	EdgeWriteAllowedToAct       = engine.NewEdge("WriteAllowedToAct").Tag("Escalation")
	EdgeAddMember               = engine.NewEdge("AddMember").Tag("Escalation")
	EdgeAddMemberGroupAttr      = engine.NewEdge("AddMemberGroupAttr").Tag("Escalation")
	EdgeAddSelfMember           = engine.NewEdge("AddSelfMember").Tag("Escalation")
	EdgeReadMSAPassword         = engine.NewEdge("ReadMSAPassword").Tag("Escalation")
	EdgeHasMSA                  = engine.NewEdge("HasMSA").Tag("Granted")
	EdgeWriteUserAccountControl = engine.NewEdge("WriteUserAccountControl").Describe("Allows attacker to set ENABLE and set DONT_REQ_PREAUTH and then to do AS_REP Kerberoasting").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		/*if uac, ok := target.AttrInt(activedirectory.UserAccountControl); ok && uac&0x0002 != 0 { //UAC_ACCOUNTDISABLE
			// Account is disabled
			return 0
		}*/
		return 50
	}).Tag("Escalation")

	EdgeWriteKeyCredentialLink = engine.NewEdge("WriteKeyCredentialLink").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			var canenable bool
			source.Edges(engine.Out).Range(func(key *engine.Object, value engine.EdgeBitmap) bool {
				if key == target {
					if value.IsSet(EdgeWriteUserAccountControl) {
						canenable = true
						return false
					}
				}
				return true
			})
			if !canenable {
				return 0
			}
		}
		return 100
	}).Tag("Escalation")
	EdgeWriteAttributeSecurityGUID           = engine.NewEdge("WriteAttrSecurityGUID").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 5 }) // Only if you patch the DC, so this will actually never work
	EdgeSIDHistoryEquality                   = engine.NewEdge("SIDHistoryEquality").Tag("Escalation")
	EdgeAllExtendedRights                    = engine.NewEdge("AllExtendedRights").Tag("Informative").RegisterProbabilityCalculator(NotAChance)
	EdgeDSReplicationSyncronize              = engine.NewEdge("DSReplSync").Tag("Granted")
	EdgeDSReplicationGetChanges              = engine.NewEdge("DSReplGetChngs").SetDefault(false, false, false).Tag("Granted")
	EdgeDSReplicationGetChangesAll           = engine.NewEdge("DSReplGetChngsAll").SetDefault(false, false, false).Tag("Granted")
	EdgeDSReplicationGetChangesInFilteredSet = engine.NewEdge("DSReplGetChngsInFiltSet").SetDefault(false, false, false).Tag("Granted")
	EdgeDCsync                               = engine.NewEdge("DCsync").Tag("Granted")
	EdgeReadLAPSPassword                     = engine.NewEdge("ReadLAPSPassword").Tag("Escalation").Tag("Granted")
	EdgeMemberOfGroup                        = engine.NewEdge("MemberOfGroup").Tag("Granted")
	EdgeMemberOfGroupIndirect                = engine.NewEdge("MemberOfGroupIndirect").SetDefault(false, false, false).Tag("Granted")
	EdgeHasSPN                               = engine.NewEdge("HasSPN").Describe("Kerberoastable by requesting Kerberos service ticket against SPN and then bruteforcing the ticket").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	}).Tag("Escalation")
	EdgeDontReqPreauth = engine.NewEdge("DontReqPreauth").Describe("Kerberoastable by AS-REP by requesting a TGT and then bruteforcing the ticket").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	}).Tag("Escalation").Tag("Granted")
	EdgeOverwritesACL              = engine.NewEdge("OverwritesACL")
	EdgeAffectedByGPO              = engine.NewEdge("AffectedByGPO").Tag("Granted")
	PartOfGPO                      = engine.NewEdge("PartOfGPO").Tag("Granted")
	EdgeLocalAdminRights           = engine.NewEdge("AdminRights").Tag("Granted")
	EdgeLocalRDPRights             = engine.NewEdge("RDPRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	EdgeLocalDCOMRights            = engine.NewEdge("DCOMRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 })
	EdgeScheduledTaskOnUNCPath     = engine.NewEdge("SchedTaskOnUNCPath")
	EdgeMachineScript              = engine.NewEdge("MachineScript")
	EdgeWriteAltSecurityIdentities = engine.NewEdge("WriteAltSecIdent").Tag("Escalation")
	EdgeWriteProfilePath           = engine.NewEdge("WriteProfilePath").Tag("Escalation")
	EdgeWriteScriptPath            = engine.NewEdge("WriteScriptPath").Tag("Escalation")
	EdgeCertificateEnroll          = engine.NewEdge("CertificateEnroll").Tag("Granted")
	EdgeCertificateAutoEnroll      = engine.NewEdge("CertificateAutoEnroll").Tag("Granted")
	EdgeVoodooBit                  = engine.NewEdge("VoodooBit")
)
