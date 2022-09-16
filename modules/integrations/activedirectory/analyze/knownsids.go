package analyze

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

const (
	DOMAIN_USER_RID_ADMIN                 = 0x000001F4
	DOMAIN_USER_RID_KRBTGT                = 0x000001F6
	DOMAIN_GROUP_RID_ADMINS               = 0x00000200
	DOMAIN_GROUP_RID_CONTROLLERS          = 0x00000204
	DOMAIN_GROUP_RID_SCHEMA_ADMINS        = 0x00000206
	DOMAIN_GROUP_RID_ENTERPRISE_ADMINS    = 0x00000207
	DOMAIN_GROUP_RID_READONLY_CONTROLLERS = 0x00000209
	DOMAIN_ALIAS_RID_ADMINS               = 0x00000220
	DOMAIN_ALIAS_RID_ACCOUNT_OPS          = 0x00000224
	DOMAIN_ALIAS_RID_SYSTEM_OPS           = 0x00000225
	DOMAIN_ALIAS_RID_PRINT_OPS            = 0x00000226
	DOMAIN_ALIAS_RID_BACKUP_OPS           = 0x00000227
	DOMAIN_ALIAS_RID_REPLICATOR           = 0x00000228
)

var (
	groupTranslationTable = map[string]windowssecurity.SID{
		strings.ToLower("Administrators"):  windowssecurity.AdministratorsSID, // EN
		strings.ToLower("Administratorer"): windowssecurity.AdministratorsSID, // DK
		strings.ToLower("Administratoren"): windowssecurity.AdministratorsSID, // DE
		strings.ToLower("Administrateurs"): windowssecurity.AdministratorsSID, // FR
		strings.ToLower("Administradores"): windowssecurity.AdministratorsSID, // ES
		strings.ToLower("Administratorzy"): windowssecurity.AdministratorsSID, // PL

		strings.ToLower("Remote Desktop Users"):       windowssecurity.RemoteDesktopUsersSID, // EN
		strings.ToLower("Brugere af Fjernskrivebord"): windowssecurity.RemoteDesktopUsersSID, // DK
	}
)

func TranslateLocalizedGroupToSID(groupname string) (windowssecurity.SID, error) {
	if sid, found := groupTranslationTable[strings.ToLower(groupname)]; found {
		return sid, nil
	}
	return windowssecurity.SID(""), errors.New("Localized group name not found")
}

func FindWellKnown(ao *engine.Objects, s windowssecurity.SID) *engine.Object {
	results, _ := ao.FindMulti(engine.ObjectSid, engine.AttributeValueSID(s))
	for _, result := range results {
		return result
	}
	return nil
}

func FindDomain(ao *engine.Objects) (ncname, netbiosname, dnsroot string, domainsid windowssecurity.SID, err error) {
	domaindns, found := ao.FindMulti(engine.ObjectClass, engine.AttributeValueString("domainDNS"))
	if !found {
		err = errors.New("No domain info found in collection")
		return
	}

	for _, domain := range domaindns {
		if domain.HasAttr(engine.ObjectSid) {
			if ncname != "" {
				err = errors.New("Found multiple domainDNS in same path - please place each set of domain objects in their own subpath")
				return
			}
			ncname = domain.OneAttrString(engine.DistinguishedName)
			domainsid = domain.SID()
		}
	}

	if ncname == "" {
		err = errors.New("Could not find domainDNS in object shard collection, giving up")
		return
	}

	// Find translation to NETBIOS name
	crossRef, found := ao.FindTwo(
		engine.ObjectClass, engine.AttributeValueString("crossRef"),
		NCName, engine.AttributeValueString(ncname),
	)
	if !found {
		err = fmt.Errorf("Could not find crossRef object for %v", ncname)
	}

	netbiosname = crossRef.OneAttrString(NetBIOSName)
	dnsroot = crossRef.OneAttrString(DNSRoot)
	found = true
	return
}
