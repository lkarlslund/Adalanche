package analyze

import (
	"encoding/json"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Machine hardening attributes, read from assessment categories. They are not
// edges on their own; they qualify a machine as a relay target, say whether
// credentials linger in memory, and record LAPS and AlwaysInstallElevated.
var (
	SMBSigningRequired   = engine.NewAttribute("sMBSigningRequired").Type(engine.AttributeTypeBool).SetDescription("The SMB server requires signing, which blocks SMB relay to it")
	SMB1Enabled          = engine.NewAttribute("sMB1Enabled").Type(engine.AttributeTypeBool).SetDescription("The deprecated SMBv1 protocol is enabled")
	LMCompatibilityLevel = engine.NewAttribute("lMCompatibilityLevel").Type(engine.AttributeTypeInt).SetDescription("LmCompatibilityLevel; below 3 allows weak NTLM/LM authentication")
	LSAProtectionRunning = engine.NewAttribute("lSAProtectionRunning").Type(engine.AttributeTypeBool).SetDescription("LSA protection (RunAsPPL) was confirmed running this boot, which hinders credential theft from LSASS")
	LAPSManagedAccount   = engine.NewAttribute("lAPSManagedAccount").SetDescription("The local account whose password LAPS manages")

	// Set in import.go from the machine's HKLM registry snapshot, read here.
	InstallerElevatedMachine = engine.NewAttribute("installerAlwaysElevatedMachine").Type(engine.AttributeTypeBool)

	// EdgeAlwaysInstallElevated: the account can install an MSI as SYSTEM on
	// the machine, because AlwaysInstallElevated is set for both the machine
	// and the user.
	EdgeAlwaysInstallElevated = engine.NewEdge("AlwaysInstallElevated").RegisterProbabilityCalculator(activedirectory.OnlyIfTargetAccountEnabled(activedirectory.FixedProbability(100))).Tag("Pivot").Describe("Can install an MSI package as SYSTEM: AlwaysInstallElevated is set for both the machine and the user")
)

// decodeInto unmarshals an assessment record, returning false on malformed data.
func decodeInto(raw json.RawMessage, v any) bool {
	return json.Unmarshal(raw, v) == nil
}

// collected reports whether a category was collected (an uncollected category
// is absence of evidence, not evidence of absence).
func collected(a *lm.Assessment, category string) bool {
	return a.Categories[category].Result.Status == "collected"
}

func importHardening(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) error {
	importSMBServerHardening(machine, a)
	importAuthenticationPolicy(machine, a)
	importLSAProtection(machine, a)
	importLAPS(machine, a)
	importAlwaysInstallElevated(tx, machine, a)
	return nil
}

func importSMBServerHardening(machine engine.TxNode, a *lm.Assessment) {
	for _, raw := range a.Categories["smb-server"].Records {
		var r struct {
			RequireSecuritySignature *bool
			EnableSMB1Protocol       *bool
		}
		if !decodeInto(raw, &r) {
			continue
		}
		if r.RequireSecuritySignature != nil {
			machine.Set(SMBSigningRequired, engine.NV(*r.RequireSecuritySignature))
			if !*r.RequireSecuritySignature {
				machine.Tag("smb_signing_not_required")
			}
		}
		if r.EnableSMB1Protocol != nil {
			machine.Set(SMB1Enabled, engine.NV(*r.EnableSMB1Protocol))
			if *r.EnableSMB1Protocol {
				machine.Tag("smb1_enabled")
			}
		}
	}
}

func importAuthenticationPolicy(machine engine.TxNode, a *lm.Assessment) {
	for _, raw := range a.Categories["authentication-policy"].Records {
		var r struct {
			Path                 string
			LmCompatibilityLevel *int64
		}
		if !decodeInto(raw, &r) {
			continue
		}
		if r.LmCompatibilityLevel != nil {
			machine.Set(LMCompatibilityLevel, engine.NV(*r.LmCompatibilityLevel))
			if *r.LmCompatibilityLevel < 3 {
				machine.Tag("weak_ntlm_authentication")
			}
		}
	}
}

func importLSAProtection(machine engine.TxNode, a *lm.Assessment) {
	if !collected(a, "lsa-protection-runtime") {
		return
	}
	// A Wininit event id 12 this boot is the runtime confirmation that LSA
	// protection started; the collector only emits the event when present.
	running := len(a.Categories["lsa-protection-runtime"].Records) > 0
	machine.Set(LSAProtectionRunning, engine.NV(running))
	if running {
		machine.Tag("lsa_protection")
	}
}

func importLAPS(machine engine.TxNode, a *lm.Assessment) {
	for _, raw := range a.Categories["password-management-policy"].Records {
		var r struct {
			Kind               string
			ManagedAccountSID  string
			ManagedAccountName string
		}
		if !decodeInto(raw, &r) || r.Kind != "active-policy-source" {
			continue
		}
		machine.Tag("laps_enabled")
		if r.ManagedAccountName != "" {
			machine.Set(LAPSManagedAccount, engine.NV(r.ManagedAccountName))
		}
	}
}

func importAlwaysInstallElevated(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) {
	// Elevation needs AlwaysInstallElevated set for both the machine (HKLM,
	// recorded as a machine attribute at import) and the user (HKCU).
	if machineOn, ok := machine.Node().AttrBool(InstallerElevatedMachine); !ok || !machineOn {
		return
	}
	for _, raw := range a.Categories["user-installer-policy"].Records {
		var r struct {
			UserSID               string
			AlwaysInstallElevated *int64
		}
		if !decodeInto(raw, &r) || r.AlwaysInstallElevated == nil || *r.AlwaysInstallElevated != 1 {
			continue
		}
		sid, err := windowssecurity.ParseStringSID(strings.TrimSpace(r.UserSID))
		if err != nil {
			continue
		}
		user := tx.FindOrAddAdjacentSID(sid, machine)
		tx.EdgeBecause(user, machine, EdgeAlwaysInstallElevated, Collected("AlwaysInstallElevated set for machine and user"))
	}
}

func init() {
	RegisterAssessmentImporter(importHardening)
}
