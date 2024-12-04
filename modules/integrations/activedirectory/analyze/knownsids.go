package analyze

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

const (
	DOMAIN_USER_RID_ADMIN                 = 0x000001F4 // Built-in Administrator account
	DOMAIN_USER_RID_KRBTGT                = 0x000001F6 // krbtgt account
	DOMAIN_GROUP_RID_ADMINS               = 0x00000200 // Domain Admins group
	DOMAIN_GROUP_RID_USERS                = 0x00000201 // Domain Users group
	DOMAIN_GROUP_RID_CONTROLLERS          = 0x00000204 // Domain Controllers group
	DOMAIN_GROUP_RID_SCHEMA_ADMINS        = 0x00000206 // Schema Admins group
	DOMAIN_GROUP_RID_ENTERPRISE_ADMINS    = 0x00000207 // Enterprise Admins group
	DOMAIN_GROUP_RID_READONLY_CONTROLLERS = 0x00000209 // Read-only Domain Controllers group
	DOMAIN_ALIAS_RID_ADMINS               = 0x00000220 // Administrators group
	DOMAIN_ALIAS_RID_ACCOUNT_OPS          = 0x00000224 // Account Operators group
	DOMAIN_ALIAS_RID_SYSTEM_OPS           = 0x00000225 // Server Operators group
	DOMAIN_ALIAS_RID_PRINT_OPS            = 0x00000226 // Print Operators group
	DOMAIN_ALIAS_RID_BACKUP_OPS           = 0x00000227 // Backup Operators group
	DOMAIN_ALIAS_RID_REPLICATOR           = 0x00000228 // Replicator group
)

var (
	nameTranslationTable = map[string]windowssecurity.SID{
		strings.ToLower("Administratorer"):            windowssecurity.AdministratorsSID,     // DK
		strings.ToLower("Interaktiv"):                 windowssecurity.InteractiveSID,        // DK
		strings.ToLower("Brugere af Fjernskrivebord"): windowssecurity.RemoteDesktopUsersSID, // DK
		strings.ToLower("Superbrugere"):               windowssecurity.PowerUsersSID,         // DK

		strings.ToLower("Administrators"):       windowssecurity.AdministratorsSID,     // EN
		strings.ToLower("Remote Desktop Users"): windowssecurity.RemoteDesktopUsersSID, // EN

		strings.ToLower("Administratoren"): windowssecurity.AdministratorsSID, // DE
		strings.ToLower("Administrateurs"): windowssecurity.AdministratorsSID, // FR
		strings.ToLower("Administradores"): windowssecurity.AdministratorsSID, // ES
		strings.ToLower("Administratorzy"): windowssecurity.AdministratorsSID, // PL

	}
)

func TranslateLocalizedNameToSID(name string) (windowssecurity.SID, error) {
	if sid, found := nameTranslationTable[strings.ToLower(name)]; found {
		return sid, nil
	}
	return windowssecurity.SID(""), errors.New("Localized group name not found")
}

func FindWellKnown(ao *engine.Objects, s windowssecurity.SID) *engine.Object {
	results, _ := ao.FindMulti(engine.ObjectSid, engine.NewAttributeValueSID(s))
	var result *engine.Object
	results.Iterate(func(o *engine.Object) bool {
		result = o
		return true
	})
	return result
}

func FindDomain(ao *engine.Objects) (domaincontext, netbiosname, dnssuffix string, domainsid windowssecurity.SID, err error) {
	domaindns, found := ao.FindMulti(engine.ObjectClass, engine.NewAttributeValueString("domainDNS"))
	if !found {
		err = errors.New("No domain info found in collection")
		return
	}

	var domain *engine.Object

	domaindns.Iterate(func(curdomain *engine.Object) bool {
		if curdomain.HasAttr(engine.ObjectSid) {
			if domain != nil {
				err = errors.New("Found multiple domainDNS in same path - please place each set of domain objects in their own subpath")
				return true
			}
			domain = curdomain
		}
		return true
	})

	if domain == nil {
		err = errors.New("Could not find domainDNS in object shard collection, giving up")
		return
	}

	return GetDomainInfo(domain, ao)
}

func GetDomainInfo(domain *engine.Object, ao *engine.Objects) (domaincontext, netbiosname, dnssuffix string, domainsid windowssecurity.SID, err error) {
	if domain.HasAttr(engine.ObjectSid) {
		if domaincontext != "" {
			err = errors.New("Found multiple domainDNS in same path - please place each set of domain objects in their own subpath")
			return
		}
		domaincontext = domain.OneAttrString(engine.DistinguishedName)
		domainsid = domain.SID()
	}

	if domaincontext == "" {
		err = errors.New("Could not find domainDNS in object shard collection, giving up")
		return
	}

	// Find translation to NETBIOS name
	crossRef, found := ao.FindTwo(
		engine.ObjectClass, engine.NewAttributeValueString("crossRef"),
		NCName, engine.NewAttributeValueString(domaincontext),
	)
	if !found {
		err = fmt.Errorf("Could not find crossRef object for %v", domaincontext)
		return
	}

	netbiosname = crossRef.OneAttrString(NetBIOSName)
	dnssuffix = crossRef.OneAttrString(DNSRoot)
	return
}
