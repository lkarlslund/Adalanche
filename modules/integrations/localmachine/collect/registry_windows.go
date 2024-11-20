package collect

import (
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var (
	collect = []string{
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
		`HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuardEnableVirtualizationBasedSecurity`,                            // Device Guard VM Protection
		`HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled`,           // Hypervisor Enforced Code Integrity
		`HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\LockConfiguration`, // Lock Configuration
		`HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled`,                                  // Secure Boot status
		`HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer`,                                               // Windows Update Server
		`HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast`,                                         // LLMNR / NetBIOS-NS
		`HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS`,                                         // mDNS (Bonjour)
		`HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*\NetbiosOptions`,                           // 0x2 = Disable NetBIOS over TCP/IP, 0x4 = Disable NetBIOS name registration
		// `HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable`,                                  // Proxy Enable
		`HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer`,                  // RDP Security Layer
		`HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication`,             // RDP User Authentication
		`HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\RestrictDriverInstallToAdministrators`, // Point and Print Restrictions
		`HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall`,         // Point and Print No Warning or Elevation on Install
		`HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdaatePromptSettings`,                 // Point and Print Update Prompt Settings
	}
)

func CollectRegistryItems() localmachine.RegistryData {
	results := make(localmachine.RegistryData)
	for _, item := range collect {
		value, err := windowssecurity.ReadRegistryKey(item)
		if err != nil {
			ui.Warn().Msgf("Could not read registry key %s: %v", item, err)
			continue
		}
		results[item] = value
	}
	return results
}
