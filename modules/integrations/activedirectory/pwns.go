package activedirectory

import "github.com/lkarlslund/adalanche/modules/engine"

func NotAChance(source, target *engine.Object) engine.Probability {
	return 0
}

var (
	EdgeACLContainsDeny = engine.NewEdge("ACLContainsDeny").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 0 }).Tag("Informative")
	EdgeResetPassword   = engine.NewEdge("ResetPassword").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&engine.UAC_ACCOUNTDISABLE != 0 {
			return -1
		}
		return 100
	}).Tag("Pivot")
	EdgeReadPasswordId = engine.NewEdge("ReadPasswordId").SetDefault(false, false, false).RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		return 5
	})
	EdgeOwns             = engine.NewEdge("Owns").Tag("Pivot")
	EdgeGenericAll       = engine.NewEdge("GenericAll").Tag("Informative")
	EdgeWriteAll         = engine.NewEdge("WriteAll").Tag("Informative").RegisterProbabilityCalculator(NotAChance)
	EdgeWritePropertyAll = engine.NewEdge("WritePropertyAll").Tag("Informative").RegisterProbabilityCalculator(NotAChance)
	EdgeWriteExtendedAll = engine.NewEdge("WriteExtendedAll").Tag("Informative").RegisterProbabilityCalculator(NotAChance)
	EdgeTakeOwnership    = engine.NewEdge("TakeOwnership").Tag("Pivot")
	EdgeWriteDACL        = engine.NewEdge("WriteDACL").Tag("Pivot")
	EdgeWriteSPN         = engine.NewEdge("WriteSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 25
		}
		return 50
	}).Tag("Pivot")
	EdgeWriteValidatedSPN = engine.NewEdge("WriteValidatedSPN").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 25
		}
		return 50
	}).Tag("Pivot")
	EdgeWriteAllowedToAct        = engine.NewEdge("WriteAllowedToAct").Tag("Pivot")
	EdgeWriteAllowedToDelegateTo = engine.NewEdge("WriteAllowedToDelegTo").Tag("Pivot")
	EdgeAddMember                = engine.NewEdge("AddMember").Tag("Pivot")
	EdgeAddMemberGroupAttr       = engine.NewEdge("AddMemberGroupAttr").Tag("Pivot")
	EdgeAddSelfMember            = engine.NewEdge("AddSelfMember").Tag("Pivot")
	EdgeReadMSAPassword          = engine.NewEdge("ReadMSAPassword").Tag("Pivot")
	EdgeHasMSA                   = engine.NewEdge("HasMSA").Tag("Granted")
	EdgeWriteUserAccountControl  = engine.NewEdge("WriteUserAccountControl").Describe("Allows attacker to set ENABLE and set DONT_REQ_PREAUTH and then to do AS_REP Kerberoasting").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		/*if uac, ok := target.AttrInt(activedirectory.UserAccountControl); ok && uac&0x0002 != 0 { //UAC_ACCOUNTDISABLE
			// Account is disabled
			return 0
		}*/
		return 50
	}).Tag("Pivot")

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
	}).Tag("Pivot")
	EdgeWriteAttributeSecurityGUID           = engine.NewEdge("WriteAttrSecurityGUID").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 0 }) // Only if you patch the DC, so this will actually never work
	EdgeSIDHistoryEquality                   = engine.NewEdge("SIDHistoryEquality").Tag("Pivot")
	EdgeAllExtendedRights                    = engine.NewEdge("AllExtendedRights").Tag("Informative").RegisterProbabilityCalculator(NotAChance)
	EdgeDSReplicationSyncronize              = engine.NewEdge("DSReplSync").Tag("Granted")
	EdgeDSReplicationGetChanges              = engine.NewEdge("DSReplGetChngs").SetDefault(false, false, false).Tag("Granted")
	EdgeDSReplicationGetChangesAll           = engine.NewEdge("DSReplGetChngsAll").SetDefault(false, false, false).Tag("Granted")
	EdgeDSReplicationGetChangesInFilteredSet = engine.NewEdge("DSReplGetChngsInFiltSet").SetDefault(false, false, false).Tag("Granted")
	EdgeDCsync                               = engine.NewEdge("DCsync").Tag("Granted")
	EdgeReadLAPSPassword                     = engine.NewEdge("ReadLAPSPassword").Tag("Pivot").Tag("Granted")
	EdgeMemberOfGroup                        = engine.NewEdge("MemberOfGroup").Tag("Granted")
	EdgeMemberOfGroupIndirect                = engine.NewEdge("MemberOfGroupIndirect").SetDefault(false, false, false).Tag("Granted")
	EdgeHasSPN                               = engine.NewEdge("HasSPN").Describe("Kerberoastable by requesting Kerberos service ticket against SPN and then bruteforcing the ticket").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	}).Tag("Pivot")
	EdgeDontReqPreauth = engine.NewEdge("DontReqPreauth").Describe("Kerberoastable by AS-REP by requesting a TGT and then bruteforcing the ticket").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		if uac, ok := target.AttrInt(UserAccountControl); ok && uac&0x0002 /*UAC_ACCOUNTDISABLE*/ != 0 {
			// Account is disabled
			return 0
		}
		return 50
	}).Tag("Pivot")
	EdgeOverwritesACL              = engine.NewEdge("OverwritesACL")
	EdgeAffectedByGPO              = engine.NewEdge("AffectedByGPO").Tag("Granted").Tag("Pivot")
	PartOfGPO                      = engine.NewEdge("PartOfGPO").Tag("Granted").Tag("Pivot")
	EdgeLocalAdminRights           = engine.NewEdge("AdminRights").Tag("Granted").Tag("Pivot")
	EdgeLocalRDPRights             = engine.NewEdge("RDPRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 }).Tag("Pivot")
	EdgeLocalDCOMRights            = engine.NewEdge("DCOMRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 }).Tag("Pivot")
	EdgeScheduledTaskOnUNCPath     = engine.NewEdge("SchedTaskOnUNCPath").Tag("Pivot")
	EdgeMachineScript              = engine.NewEdge("MachineScript").Tag("Pivot")
	EdgeWriteAltSecurityIdentities = engine.NewEdge("WriteAltSecIdent").Tag("Pivot")
	EdgeWriteProfilePath           = engine.NewEdge("WriteProfilePath").Tag("Pivot")
	EdgeWriteScriptPath            = engine.NewEdge("WriteScriptPath").Tag("Pivot")
	EdgeCertificateEnroll          = engine.NewEdge("CertificateEnroll").Tag("Granted")
	EdgeCertificateAutoEnroll      = engine.NewEdge("CertificateAutoEnroll").Tag("Granted")
	EdgeVoodooBit                  = engine.NewEdge("VoodooBit").SetDefault(false, false, false).Tag("Internal").Hidden()
)
