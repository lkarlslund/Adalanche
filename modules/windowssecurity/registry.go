//go:build windows
// +build windows

package windowssecurity

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lkarlslund/adalanche/modules/ui"
	"golang.org/x/sys/windows/registry"
)

func ReadRegistryKey(item string) (any, error) {
	if strings.Index(item, `*`) != -1 {
		// Globbing not supported yet ... let's see later :-)
		return nil, errors.New("globbing not supported yet")
	}

	regparts := strings.Split(item, "\\")

	keypath := strings.Join(regparts[1:len(regparts)-1], "\\")
	valuename := regparts[len(regparts)-1]
	hivename := regparts[0]

	var hive registry.Key
	switch strings.ToUpper(strings.TrimSuffix(hivename, ":")) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hive = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		hive = registry.CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		hive = registry.CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		hive = registry.USERS
	case "HKCC", "HKEY_CURRENT_CONFIG":
		hive = registry.CURRENT_CONFIG
	default:
		return nil, fmt.Errorf("Unsupported registry hive name %v, skipping %v", hive, item)
	}

	var value any

	k, err := registry.OpenKey(hive, keypath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		ui.Warn().Msgf("Problem opening registry key %v (%v) / %v: %v", hivename, hive, keypath, err)
		return nil, err
	}
	defer k.Close()

	var valtype uint32
	value, valtype, err = k.GetStringValue(valuename)
	if err != nil {
		if err == registry.ErrUnexpectedType {
			switch valtype {
			case registry.NONE, registry.LINK, registry.RESOURCE_LIST, registry.FULL_RESOURCE_DESCRIPTOR, registry.RESOURCE_REQUIREMENTS_LIST:
				// skip trying
				return nil, fmt.Errorf("Unsupported registry type %v for key %v", valtype, valuename)
			case registry.SZ, registry.EXPAND_SZ:
				// strange, that should have worked
			case registry.BINARY:
				value, _, err = k.GetBinaryValue(valuename)
			case registry.DWORD, registry.QWORD:
				value, _, err = k.GetIntegerValue(valuename)
			case registry.MULTI_SZ:
				value, _, err = k.GetStringsValue(valuename)
			}
		} else {
			return nil, fmt.Errorf("Problem getting registry value %v: %v", item, err)
		}
	}
	if err != nil {
		ui.Warn().Msgf("Problem reading registry value %v: %v", valuename, err)
	}
	return value, err
}
