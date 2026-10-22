package activedirectory

import "github.com/lkarlslund/adalanche/modules/engine"

// User rights (privileges and logon rights) become edges from the account
// holding the right to the machine it holds it on, after
// https://github.com/gtworek/Priv2Admin. A machine's rights are known from
// its own collection, or from the GPOs that apply to it.

var (
	EdgeSeBackupPrivilege        = engine.NewEdge("SeBackupPrivilege")
	EdgeSeRestorePrivilege       = engine.NewEdge("SeRestorePrivilege")
	EdgeSeTakeOwnershipPrivilege = engine.NewEdge("SeTakeOwnershipPrivilege")

	EdgeSeAssignPrimaryToken   = engine.NewEdge("SeAssignPrimaryToken").Tag("Pivot")
	EdgeSeCreateToken          = engine.NewEdge("SeCreateToken").Tag("Pivot")
	EdgeSeDebug                = engine.NewEdge("SeDebug").Tag("Pivot")
	EdgeSeImpersonate          = engine.NewEdge("SeImpersonate").RegisterProbabilityCalculator(FixedProbability(20)).Tag("Pivot")
	EdgeSeLoadDriver           = engine.NewEdge("SeLoadDriver").Tag("Pivot")
	EdgeSeManageVolume         = engine.NewEdge("SeManageVolume").Tag("Pivot")
	EdgeSeTakeOwnership        = engine.NewEdge("SeTakeOwnership").Tag("Pivot")
	EdgeSeTrustedCredManAccess = engine.NewEdge("SeTrustedCredManAccess").Tag("Pivot")
	EdgeSeTcb                  = engine.NewEdge("SeTcb").Tag("Pivot")

	EdgeSeNetworkLogonRight = engine.NewEdge("SeNetworkLogonRight").RegisterProbabilityCalculator(FixedProbability(10))

	// EdgeSeMachineAccountPrivilege: "Add workstations to domain" on the
	// machine. It only means something on a domain controller, where it lets
	// the account add computer accounts to the domain.
	EdgeSeMachineAccountPrivilege = engine.NewEdge("SeMachineAccountPrivilege").Tag("Informative").RegisterFixedProbability(0).SetDefault(false, false, false).
					Describe("Holds \"Add workstations to domain\" (SeMachineAccountPrivilege) on the machine; on a domain controller this lets it add computer accounts to the domain")
)

// PrivilegeEdge returns the edge holding a user right gives on a machine, or
// false for rights that give none.
func PrivilegeEdge(right string) (engine.Edge, bool) {
	switch right {
	case "SeNetworkLogonRight":
		return EdgeSeNetworkLogonRight, true
	case "SeRemoteInteractiveLogonRight":
		return EdgeLocalRDPRights, true
	case "SeBackupPrivilege":
		return EdgeSeBackupPrivilege, true
	case "SeRestorePrivilege":
		return EdgeSeRestorePrivilege, true
	case "SeAssignPrimaryTokenPrivilege":
		return EdgeSeAssignPrimaryToken, true
	case "SeCreateTokenPrivilege":
		return EdgeSeCreateToken, true
	case "SeDebugPrivilege":
		return EdgeSeDebug, true
	case "SeImpersonatePrivilege":
		return EdgeSeImpersonate, true
	case "SeLoadDriverPrivilege":
		return EdgeSeLoadDriver, true
	case "SeManageVolumePrivilege":
		return EdgeSeManageVolume, true
	case "SeTakeOwnershipPrivilege":
		return EdgeSeTakeOwnership, true
	case "SeTrustedCredManAccess":
		return EdgeSeTrustedCredManAccess, true
	case "SeMachineAccountPrivilege":
		return EdgeSeMachineAccountPrivilege, true
	case "SeTcbPrivilege":
		return EdgeSeTcb, true
	}
	return engine.NonExistingEdge, false
}

// DenyingRight is the right that takes a logon right away, if any.
func DenyingRight(right string) string {
	switch right {
	case "SeNetworkLogonRight":
		return "SeDenyNetworkLogonRight"
	case "SeRemoteInteractiveLogonRight":
		return "SeDenyRemoteInteractiveLogonRight"
	}
	return ""
}
