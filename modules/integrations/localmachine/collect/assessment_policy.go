package collect

import "github.com/lkarlslund/adalanche/modules/basedata"

// Policy roots do not inherit values from one another. Unknown higher-priority
// roots prevent a claim about which lower-priority root is active.
func selectPasswordPolicy(policies []map[string]any) (int, bool) {
	for i, policy := range policies {
		result, ok := policy["Result"].(basedata.CollectionResult)
		if !ok {
			return -1, false
		}
		if result.Status == basedata.CollectionNotFound {
			continue
		}
		if result.Status != basedata.CollectionCollected {
			return -1, false
		}
		has, known := policy["HasExplicitSettings"].(bool)
		if !known {
			return -1, false
		}
		if has {
			return i, true
		}
	}
	return -1, true
}

func passwordIdentitySettingsKnown(policy map[string]any, legacy bool) bool {
	results, ok := policy["ValueResults"].(map[string]any)
	if !ok {
		return false
	}
	fields := []string{"AdministratorAccountName", "AutomaticAccountManagementEnabled"}
	if legacy {
		fields = []string{"AdminAccountName"}
	}
	for _, field := range fields {
		result, ok := results[field].(basedata.CollectionResult)
		if !ok {
			return false
		}
		if result.Status != basedata.CollectionCollected && result.Status != basedata.CollectionNotFound {
			return false
		}
	}
	return true
}
