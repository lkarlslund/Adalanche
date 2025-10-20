package activedirectory

import (
	"github.com/lkarlslund/adalanche/modules/engine"
)

func OnlyIfTargetAccountEnabled(wrapped engine.ProbabilityCalculatorFunction) engine.ProbabilityCalculatorFunction {
	return func(source, target *engine.Node, edges *engine.EdgeBitmap) engine.Probability {
		if target.Type() != engine.NodeTypeUser || target.HasTag("account_enabled") || edges.IsSet(EdgeWriteUserAccountControl) {
			return wrapped(source, target, edges)
		}
		return 0
	}
}

func FixedProbability(probability int) engine.ProbabilityCalculatorFunction {
	return func(source, target *engine.Node, edge *engine.EdgeBitmap) engine.Probability {
		return engine.Probability(probability)
	}
}

var (
	EdgeACLContainsDeny  = engine.NewEdge("ACLContainsDeny").RegisterProbabilityCalculator(FixedProbability(0)).Tag("Informative")
	EdgeResetPassword    = engine.NewEdge("ResetPassword").RegisterProbabilityCalculator(OnlyIfTargetAccountEnabled(FixedProbability(100))).Tag("Pivot")
	EdgeReadPasswordId   = engine.NewEdge("ReadPasswordId").SetDefault(false, false, false).RegisterProbabilityCalculator(FixedProbability(5))
	EdgeOwns             = engine.NewEdge("Owns").Tag("Pivot")
	EdgeGenericAll       = engine.NewEdge("GenericAll").Tag("Informative")
	EdgeWriteAll         = engine.NewEdge("WriteAll").Tag("Informative").RegisterProbabilityCalculator(FixedProbability(0))
	EdgeWritePropertyAll = engine.NewEdge("WritePropertyAll").Tag("Informative").RegisterProbabilityCalculator(FixedProbability(0))
	EdgeWriteExtendedAll = engine.NewEdge("WriteExtendedAll").Tag("Informative").RegisterProbabilityCalculator(FixedProbability(0))
	EdgeTakeOwnership    = engine.NewEdge("TakeOwnership").Tag("Pivot")
	EdgeWriteDACL        = engine.NewEdge("WriteDACL").Tag("Pivot")

	// Kerberoasting
	calculateKerberoast = func(source, target *engine.Node, edges *engine.EdgeBitmap) engine.Probability {
		if target.HasTag("account_active") {
			// Get password age
			pwdage := target.OneAttr(MetaPasswordAge)
			if pwdage != nil {
				if age, ok := pwdage.Raw().(int64); ok {
					// Just set passwords ate 20% success, up to 80% for 10 year old passwords
					tenyears := 24 * 365 * 10
					if int(age) > tenyears {
						return 80
					}
					risk := (80 * int(age)) / tenyears
					if risk < 20 {
						return 20
					}
					return engine.Probability(risk)
				}
			}
			return 50
		}
		return 0
	}

	EdgeWriteSPN          = engine.NewEdge("WriteSPN").RegisterProbabilityCalculator(calculateKerberoast).Tag("Pivot")
	EdgeWriteValidatedSPN = engine.NewEdge("WriteValidatedSPN").RegisterProbabilityCalculator(calculateKerberoast).Tag("Pivot")
	EdgeHasSPN            = engine.NewEdge("HasSPN").Describe("Kerberoastable by requesting Kerberos service ticket against SPN and then bruteforcing the ticket").RegisterProbabilityCalculator(calculateKerberoast).Tag("Pivot")
	EdgeDontReqPreauth    = engine.NewEdge("DontReqPreauth").Describe("Kerberoastable by AS-REP by requesting a TGT and then bruteforcing the ticket").RegisterProbabilityCalculator(calculateKerberoast).Tag("Pivot")

	EdgeWriteAllowedToAct        = engine.NewEdge("WriteAllowedToAct").Tag("Pivot")
	EdgeWriteAllowedToDelegateTo = engine.NewEdge("WriteAllowedToDelegTo").Tag("Pivot")
	EdgeAddMember                = engine.NewEdge("AddMember").Tag("Pivot")
	EdgeAddMemberGroupAttr       = engine.NewEdge("AddMemberGroupAttr").Tag("Pivot")
	EdgeAddSelfMember            = engine.NewEdge("AddSelfMember").Tag("Pivot")
	EdgeReadGMSAPassword         = engine.NewEdge("ReadGMSAPassword").Tag("Pivot")
	EdgeHasMSA                   = engine.NewEdge("HasMSA").Tag("Granted")
	EdgeWriteUserAccountControl  = engine.NewEdge("WriteUserAccountControl").Describe("Allows attacker to set ENABLE and set DONT_REQ_PREAUTH and then to do AS_REP Kerberoasting").RegisterProbabilityCalculator(func(source, target *engine.Node, edges *engine.EdgeBitmap) engine.Probability {
		/*if uac, ok := target.AttrInt(activedirectory.UserAccountControl); ok && uac&0x0002 != 0 { //UAC_ACCOUNTDISABLE
			// Account is disabled
			return 0
		}*/
		return 50
	}).Tag("Pivot")

	EdgeWriteKeyCredentialLink = engine.NewEdge("WriteKeyCredentialLink").RegisterProbabilityCalculator(func(source, target *engine.Node, edges *engine.EdgeBitmap) engine.Probability {
		if target.HasTag("account_enabled") || edges.IsSet(EdgeWriteUserAccountControl) {
			return 100
		}
		return 0
	}).Tag("Pivot")
	EdgeWriteAttributeSecurityGUID           = engine.NewEdge("WriteAttrSecurityGUID").RegisterProbabilityCalculator(FixedProbability(0)) // Only if you patch the DC, so this will actually never work
	EdgeSIDHistoryEquality                   = engine.NewEdge("SIDHistoryEquality").Tag("Pivot")
	EdgeAllExtendedRights                    = engine.NewEdge("AllExtendedRights").Tag("Informative").RegisterProbabilityCalculator(FixedProbability(0))
	EdgeDSReplicationSyncronize              = engine.NewEdge("DSReplSync").Tag("Granted").SetDefault(false, false, false).Tag("Granted").RegisterProbabilityCalculator(FixedProbability(0))
	EdgeDSReplicationGetChanges              = engine.NewEdge("DSReplGetChngs").SetDefault(false, false, false).Tag("Granted").Tag("Granted").RegisterProbabilityCalculator(FixedProbability(0))
	EdgeDSReplicationGetChangesAll           = engine.NewEdge("DSReplGetChngsAll").SetDefault(false, false, false).Tag("Granted").Tag("Granted").RegisterProbabilityCalculator(FixedProbability(0))
	EdgeDSReplicationGetChangesInFilteredSet = engine.NewEdge("DSReplGetChngsInFiltSet").SetDefault(false, false, false).Tag("Granted").Tag("Granted").RegisterProbabilityCalculator(FixedProbability(0))
	EdgeCall                                 = engine.NewEdge("Call").Describe("Call a service point")
	EdgeControls                             = engine.NewEdge("Controls").Describe("Node controls a service point")
	EdgeReadLAPSPassword                     = engine.NewEdge("ReadLAPSPassword").Tag("Pivot").Tag("Granted")
	EdgeMemberOfGroup                        = engine.NewEdge("MemberOfGroup").Tag("Granted")
	EdgeMemberOfGroupIndirect                = engine.NewEdge("MemberOfGroupIndirect").SetDefault(false, false, false).Tag("Granted")
	EdgeOverwritesACL                        = engine.NewEdge("OverwritesACL")
	EdgeAffectedByGPO                        = engine.NewEdge("AffectedByGPO").Tag("Granted").Tag("Pivot")
	PartOfGPO                                = engine.NewEdge("PartOfGPO").Tag("Granted").Tag("Pivot")
	EdgeLocalAdminRights                     = engine.NewEdge("AdminRights").Tag("Granted").Tag("Pivot")
	EdgeLocalRDPRights                       = engine.NewEdge("RDPRights").RegisterProbabilityCalculator(FixedProbability(30)).Tag("Pivot")
	EdgeLocalDCOMRights                      = engine.NewEdge("DCOMRights").RegisterProbabilityCalculator(FixedProbability(30)).Tag("Pivot")
	EdgeScheduledTaskOnUNCPath               = engine.NewEdge("SchedTaskOnUNCPath").Tag("Pivot")
	EdgeMachineScript                        = engine.NewEdge("MachineScript").Tag("Pivot")
	EdgeWriteAltSecurityIdentities           = engine.NewEdge("WriteAltSecIdent").Tag("Pivot").RegisterProbabilityCalculator(OnlyIfTargetAccountEnabled(FixedProbability(100)))
	EdgeWriteProfilePath                     = engine.NewEdge("WriteProfilePath").Tag("Pivot")
	EdgeWriteScriptPath                      = engine.NewEdge("WriteScriptPath").Tag("Pivot")
	EdgeCertificateEnroll                    = engine.NewEdge("CertificateEnroll").Tag("Granted")
	EdgeCertificateAutoEnroll                = engine.NewEdge("CertificateAutoEnroll").Tag("Granted")
	EdgeVoodooBit                            = engine.NewEdge("VoodooBit").SetDefault(false, false, false).Tag("Internal").Hidden()
)
