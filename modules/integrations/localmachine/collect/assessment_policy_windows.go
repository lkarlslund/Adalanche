//go:build windows

package collect

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func collectPolicyProvenance(c *assessmentCapture) error {
	// The AD site the machine places itself in decides which site-linked
	// GPOs apply. Netlogon keeps the discovered site, and an administrator
	// override if one is configured.
	site := map[string]any{"Class": "MachineSite", "Source": "netlogon", "Scope": "machine"}
	registryStrings(c, registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`, site, []string{"DynamicSiteName", "SiteName"}, nil)
	if err := c.add(site); err != nil {
		return err
	}

	namespaces := []string{`root\RSOP\Computer`}
	err := wmiRecords(c, `root\RSOP\User`, "__Namespace", []string{"Name"}, "", func(r map[string]any) error {
		name, _ := r["Name"].(string)
		if !strings.HasPrefix(name, "S_") || strings.ContainsAny(name, `\/'"`) {
			return errors.ErrUnsupported
		}
		if len(namespaces) >= 256 {
			return errAssessmentLimit
		}
		namespaces = append(namespaces, `root\RSOP\User\`+name)
		return nil
	})
	c.failure(nativeCollectionResult(err))
	if err := c.operation("cached-user-rsop-namespaces", err); err != nil {
		return err
	}
	for _, namespace := range namespaces {
		for _, query := range []struct {
			class  string
			fields []string
		}{
			{"RSOP_GPO", []string{"id", "name", "guidName", "version", "enabled", "accessDenied", "filterAllowed", "fileSystemPath"}},
			{"RSOP_RegistryPolicySetting", []string{"id", "GPOID", "SOMID", "precedence", "creationTime", "registryKey", "valueName", "valueType", "deleted"}},
			{"RSOP_ExtensionStatus", []string{"extensionGuid", "beginTime", "endTime", "loggingStatus", "error"}},
		} {
			err := wmiRecords(c, namespace, query.class, query.fields, "", func(r map[string]any) error {
				r["Namespace"], r["Class"], r["Source"] = namespace, query.class, "cached-rsop"
				r["Scope"] = "machine"
				if strings.Contains(namespace, `\User\`) {
					r["Scope"] = "user"
					r["UserSID"] = strings.ReplaceAll(strings.TrimPrefix(namespace, `root\RSOP\User\`), "_", "-")
				}
				return c.add(r)
			})
			c.failure(nativeCollectionResult(err))
			if errors.Is(err, errAssessmentLimit) {
				return err
			}
			if err := c.operation(namespace+":"+query.class, err); err != nil {
				return err
			}
		}
	}
	return nil
}

// Fields are allowlisted by type. Never enumerate or serialize arbitrary values.
func registryStrings(c *assessmentCapture, root registry.Key, path string, record map[string]any, stringsFields, multiFields []string) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			c.failure(nativeCollectionResult(err))
		}
		return
	}
	defer key.Close()
	results, _ := record["ValueResults"].(map[string]any)
	if results == nil {
		results = map[string]any{}
		record["ValueResults"] = results
	}
	for _, name := range stringsFields {
		value, _, err := key.GetStringValue(name)
		if len(value) > 64<<10 {
			err = errAssessmentLimit
			value = ""
		}
		results[name] = nativeCollectionResult(err)
		if err == nil {
			record[name] = value
		} else if !errors.Is(err, registry.ErrNotExist) {
			c.failure(nativeCollectionResult(err))
		}
	}
	for _, name := range multiFields {
		value, _, err := key.GetStringsValue(name)
		if len(value) > 1024 {
			err = errAssessmentLimit
			value = nil
		}
		results[name] = nativeCollectionResult(err)
		if err == nil {
			record[name] = value
		} else if !errors.Is(err, registry.ErrNotExist) {
			c.failure(nativeCollectionResult(err))
		}
	}
}

func collectAuthenticationPolicy(c *assessmentCapture) error {
	for _, q := range []struct {
		path                 string
		numbers, text, multi []string
	}{
		{`SYSTEM\CurrentControlSet\Services\LDAP`, []string{"LDAPClientIntegrity"}, nil, nil},
		{`SYSTEM\CurrentControlSet\Services\NTDS\Parameters`, []string{"LDAPServerIntegrity", "LdapEnforceChannelBinding", "LDAPServerRequireSigning"}, nil, nil},
		{`SYSTEM\CurrentControlSet\Control\Lsa`, []string{"LmCompatibilityLevel", "NoLMHash", "RestrictAnonymous", "RestrictAnonymousSAM", "EveryoneIncludesAnonymous"}, nil, nil},
		{`SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`, []string{"NtlmMinClientSec", "NtlmMinServerSec", "RestrictSendingNTLMTraffic", "RestrictReceivingNTLMTraffic", "AuditReceivingNTLMTraffic"}, nil, []string{"ClientAllowedNTLMServers"}},
		{`SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`, []string{"RestrictNTLMInDomain", "AuditNTLMInDomain", "RequireSignOrSeal", "RequireStrongKey", "SealSecureChannel", "SignSecureChannel"}, nil, []string{"DCAllowedNTLMServers"}},
		{`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, []string{"RequireSecuritySignature", "EnableSecuritySignature", "EncryptData", "RejectUnencryptedAccess"}, nil, nil},
		{`SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`, []string{"RequireSecuritySignature", "EnableSecuritySignature", "AllowInsecureGuestAuth"}, nil, nil},
	} {
		r, err := registryAssessment(c, registry.LOCAL_MACHINE, q.path, q.numbers)
		if err != nil {
			return err
		}
		r["Scope"], r["EffectiveRuntimeKnown"] = "machine-registry", false
		registryStrings(c, registry.LOCAL_MACHINE, q.path, r, q.text, q.multi)
		if err := c.add(r); err != nil {
			return err
		}
	}
	return nil
}

func collectSMBConnections(c *assessmentCapture) error {
	for _, q := range []struct {
		class  string
		fields []string
	}{
		{"MSFT_SmbConnection", []string{"ServerName", "ShareName", "UserName", "Dialect", "Signed", "Encrypted", "NumOpens"}},
		{"MSFT_SmbSession", []string{"SessionId", "ClientComputerName", "ClientUserName", "Dialect", "NumOpens", "SecondsExists", "SecondsIdle"}},
	} {
		err := wmiRecords(c, `root\Microsoft\Windows\SMB`, q.class, q.fields, "", func(r map[string]any) error { r["Class"] = q.class; return c.add(r) })
		c.failure(nativeCollectionResult(err))
		if err := c.operation(q.class, err); err != nil {
			return err
		}
	}
	return nil
}
