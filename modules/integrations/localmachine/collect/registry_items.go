package collect

import (
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

const (
	netbiosInterfacesRegistryPath = `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`
	netbiosOptionsValueName       = "NetbiosOptions"
)

var registryItems = []string{
	`HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`, // Check LSA Protection

	`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`,    // UAC Prompt Behavior (Administrator)
	`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`,                     // Check UAC Level
	`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`, // Local Account Token Filter Policy
	`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`,         // Prompt on Secure Desktop
	`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`,      // Filter Administrator Token

	`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`,                                              // Initial Shell(s)
	`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`,                                           // Userinit (Logon Script)
	`HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`,                                      // Always Install Elevated
	`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer\DisableCoInstallers`,                           // 3rd Party Software Installation
	`HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceLock\AllowDirectMemoryAccess`,                                   // Bypass DMA Restrictions
	`HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity`,                           // Device Guard VM Protection
	`HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled`,           // Hypervisor Enforced Code Integrity
	`HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\LockConfiguration`, // Lock Configuration
	`HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled`,                                  // Secure Boot status
	`HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer`,                                               // Windows Update Server
	`HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast`,                                         // LLMNR / NetBIOS-NS
	`HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS`,                                         // mDNS (Bonjour)
	// `HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable`, // Proxy Enable
	`HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer`,                  // RDP Security Layer
	`HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication`,             // RDP User Authentication
	`HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallToAdministrators`, // Point and Print Restrictions
	`HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall`,         // Point and Print No Warning or Elevation on Install
	`HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings`,                  // Point and Print Update Prompt Settings
}

type registryValueReader func(string) (any, error)
type registrySubkeyReader func(string) ([]string, error)

func netbiosOptionRegistryItem(interfaceKey string) string {
	return netbiosInterfacesRegistryPath + `\` + interfaceKey + `\` + netbiosOptionsValueName
}

func registryCollectionItems(interfaceKeys []string) []string {
	items := append([]string(nil), registryItems...)
	for _, interfaceKey := range interfaceKeys {
		items = append(items, netbiosOptionRegistryItem(interfaceKey))
	}
	return items
}

func collectRegistryItems(readValue registryValueReader, readSubkeys registrySubkeyReader) localmachine.RegistryData {
	var interfaceItems []string
	if readSubkeys != nil {
		interfaceKeys, err := readSubkeys(netbiosInterfacesRegistryPath)
		if err != nil {
			ui.Warn().Msgf("Could not enumerate NetBIOS interfaces at %s: %v", netbiosInterfacesRegistryPath, err)
		} else {
			interfaceItems = interfaceKeys
		}
	}

	results := make(localmachine.RegistryData)
	for _, item := range registryCollectionItems(interfaceItems) {
		value, err := readValue(item)
		if err != nil {
			ui.Warn().Msgf("Could not read registry key %s: %v", item, err)
			continue
		}
		results[item] = value
	}
	return results
}
