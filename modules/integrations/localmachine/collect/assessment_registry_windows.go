//go:build windows

package collect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"golang.org/x/sys/windows/registry"
)

func collectCredentialLocations(c *assessmentCapture) error {
	profiles, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.READ)
	if err != nil {
		return err
	}
	defer profiles.Close()
	names, err := profiles.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}
	for _, sid := range names {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		profile, err := registry.OpenKey(profiles, sid, registry.QUERY_VALUE)
		if err != nil {
			c.failure(nativeCollectionResult(err))
			continue
		}
		path, _, err := profile.GetStringValue("ProfileImagePath")
		// When the profile was last loaded and unloaded, as FILETIME halves.
		filetime := func(name string) time.Time {
			high, _, highErr := profile.GetIntegerValue(name + "High")
			low, _, lowErr := profile.GetIntegerValue(name + "Low")
			if highErr != nil || lowErr != nil {
				return time.Time{}
			}
			return filetimeToTime(high, low)
		}
		loaded, unloaded := filetime("LocalProfileLoadTime"), filetime("LocalProfileUnloadTime")
		profile.Close()
		if err != nil {
			c.failure(nativeCollectionResult(err))
			continue
		}
		path, err = registry.ExpandString(path)
		if err != nil {
			c.failure(nativeCollectionResult(err))
			continue
		}
		// The profile shows the account logged on here; its credential
		// locations show whether it saved any secrets.
		record := map[string]any{"Kind": "profile", "UserSID": sid, "ProfilePath": path}
		if !loaded.IsZero() {
			record["LastLoaded"] = loaded
		}
		if !unloaded.IsZero() {
			record["LastUnloaded"] = unloaded
		}
		// For Windows versions without the load times: the user's registry
		// hive is written while the profile is loaded and when it unloads,
		// and the profile folder was made at the first logon.
		if hive, err := os.Stat(filepath.Join(path, "NTUSER.DAT")); err == nil {
			record["NTUserModified"] = hive.ModTime().UTC()
		}
		if folder, err := os.Stat(path); err == nil {
			if data, ok := folder.Sys().(*syscall.Win32FileAttributeData); ok {
				record["ProfileCreated"] = time.Unix(0, data.CreationTime.Nanoseconds()).UTC()
			}
		}
		if err := c.add(record); err != nil {
			return err
		}
		for _, location := range credentialLocations {
			dir := filepath.Join(path, location.Relative)
			files, exists, countErr := countCredentialFiles(location.Kind, dir)
			record := map[string]any{"Kind": location.Kind, "UserSID": sid, "Path": dir, "Exists": exists, "Files": files}
			if countErr != nil {
				result := nativeCollectionResult(countErr)
				record["CountResult"] = result
				c.failure(result)
			}
			if err := c.add(record); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectPasswordPolicy(c *assessmentCapture, info *lm.Info) error {
	var policies []map[string]any
	for priority, path := range []string{`SOFTWARE\Microsoft\Policies\LAPS`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`, `SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config`, `SOFTWARE\Policies\Microsoft Services\AdmPwd`} {
		record, err := registryAssessment(c, registry.LOCAL_MACHINE, path, []string{"BackupDirectory", "PasswordAgeDays", "PasswordLength", "PasswordComplexity", "ADPasswordEncryptionEnabled", "PostAuthenticationActions", "AdmPwdEnabled", "PostAuthenticationResetDelay", "ADEncryptedPasswordHistorySize", "ADBackupDSRMPassword", "PasswordExpirationProtectionEnabled", "PassphraseLength", "AutomaticAccountManagementEnabled", "AutomaticAccountManagementTarget", "AutomaticAccountManagementEnableAccount", "AutomaticAccountManagementRandomizeName"})
		if err != nil {
			return err
		}
		record["Priority"] = priority
		registryStrings(c, registry.LOCAL_MACHINE, path, record, []string{"AdministratorAccountName", "AdminAccountName", "ADPasswordEncryptionPrincipal", "AutomaticAccountManagementNameOrPrefix"}, nil)
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err == nil {
			names, namesErr := key.ReadValueNames(-1)
			key.Close()
			record["SettingsEnumerationResult"] = nativeCollectionResult(namesErr)
			if namesErr == nil {
				record["HasExplicitSettings"] = len(names) > 0
			} else {
				c.failure(nativeCollectionResult(namesErr))
			}
		}
		policies = append(policies, record)
		if err := c.add(record); err != nil {
			return err
		}
	}
	selected, known := selectPasswordPolicy(policies)
	r := map[string]any{"Kind": "active-policy-source", "SelectionKnown": known, "RuntimeVerified": false, "DefaultsApplied": false}
	if selected >= 0 {
		policy := policies[selected]
		r["Path"] = policy["Path"]
		name, _ := policy["AdministratorAccountName"].(string)
		if selected == 3 {
			name, _ = policy["AdminAccountName"].(string)
		}
		if passwordIdentitySettingsKnown(policy, selected == 3) && policy["AutomaticAccountManagementEnabled"] != uint64(1) {
			for _, user := range info.Users {
				if (name != "" && strings.EqualFold(name, user.Name)) || (name == "" && strings.HasSuffix(user.SID, "-500")) {
					r["ManagedAccountName"], r["ManagedAccountSID"], r["IdentitySource"] = user.Name, user.SID, "policy-and-local-inventory"
				}
			}
		} else {
			r["IdentityUnresolvedReason"] = "automatic-or-unreadable-account-configuration"
		}
	}
	return c.add(r)
}

func collectUserInstallerPolicy(c *assessmentCapture) error {
	names, err := registry.USERS.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}
	for _, sid := range names {
		if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "_Classes") {
			continue
		}
		record, err := registryAssessment(c, registry.USERS, sid+`\Software\Policies\Microsoft\Windows\Installer`, []string{"AlwaysInstallElevated"})
		if err != nil {
			return err
		}
		record["UserSID"] = sid
		if err := c.add(record); err != nil {
			return err
		}
	}
	return nil
}

func registryAssessment(c *assessmentCapture, root registry.Key, path string, fields []string) (map[string]any, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	record := map[string]any{"Path": path}
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	record["Result"] = nativeCollectionResult(err)
	if err != nil {
		// Absent policy is valid evidence. Denied/failed reads are not absence.
		if errors.Is(err, registry.ErrNotExist) {
			record["Present"] = false
		} else {
			c.failure(nativeCollectionResult(err))
		}
		return record, nil
	}
	defer key.Close()
	record["Present"] = true
	results := map[string]any{}
	for _, field := range fields {
		value, _, err := key.GetIntegerValue(field)
		results[field] = nativeCollectionResult(err)
		if err == nil {
			record[field] = value
		} else {
			record[field] = nil
			if !errors.Is(err, registry.ErrNotExist) {
				c.failure(nativeCollectionResult(err))
			}
		}
	}
	record["ValueResults"] = results
	return record, nil
}
