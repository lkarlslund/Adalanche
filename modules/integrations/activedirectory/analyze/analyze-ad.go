package analyze

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
)

// Interesting permissions on AD
var (
	ResetPwd                                = uuid.UUID{0x00, 0x29, 0x95, 0x70, 0x24, 0x6d, 0x11, 0xd0, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29}
	DSReplicationGetChanges                 = uuid.UUID{0x11, 0x31, 0xf6, 0xaa, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationGetChangesAll              = uuid.UUID{0x11, 0x31, 0xf6, 0xad, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationSyncronize                 = uuid.UUID{0x11, 0x31, 0xf6, 0xab, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationGetChangesInFilteredSet, _ = uuid.FromString("{89e95b76-444d-4c62-991a-0facbeda640c}")

	AttributeMember                                 = uuid.UUID{0xbf, 0x96, 0x79, 0xc0, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	AttributeSetGroupMembership, _                  = uuid.FromString("{BC0AC240-79A9-11D0-9020-00C04FC2D4CF}")
	AttributeSIDHistory                             = uuid.UUID{0x17, 0xeb, 0x42, 0x78, 0xd1, 0x67, 0x11, 0xd0, 0xb0, 0x02, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	AttributeAllowedToActOnBehalfOfOtherIdentity, _ = uuid.FromString("{3F78C3E5-F79A-46BD-A0B8-9D18116DDC79}")
	AttributeMSDSGroupMSAMembership                 = uuid.UUID{0x88, 0x8e, 0xed, 0xd6, 0xce, 0x04, 0xdf, 0x40, 0xb4, 0x62, 0xb8, 0xa5, 0x0e, 0x41, 0xba, 0x38}
	AttributeGPLink, _                              = uuid.FromString("{F30E3BBE-9FF0-11D1-B603-0000F80367C1}")
	AttributeMSDSKeyCredentialLink, _               = uuid.FromString("{5B47D60F-6090-40B2-9F37-2A4DE88F3063}")
	AttributeSecurityGUIDGUID, _                    = uuid.FromString("{bf967924-0de6-11d0-a285-00aa003049e2}")
	AttributeAltSecurityIdentitiesGUID, _           = uuid.FromString("{00FBF30C-91FE-11D1-AEBC-0000F80367C1}")
	AttributeProfilePathGUID, _                     = uuid.FromString("{bf967a05-0de6-11d0-a285-00aa003049e2}")
	AttributeScriptPathGUID, _                      = uuid.FromString("{bf9679a8-0de6-11d0-a285-00aa003049e2}")
	AttributeMSDSManagedPasswordId, _               = uuid.FromString("0e78295a-c6d3-0a40-b491-d62251ffa0a6")

	ExtendedRightCertificateEnroll, _ = uuid.FromString("0e10c968-78fb-11d2-90d4-00c04f79dc55")

	ValidateWriteSelfMembership, _ = uuid.FromString("bf9679c0-0de6-11d0-a285-00aa003049e2")
	ValidateWriteSPN, _            = uuid.FromString("f3a64788-5306-11d1-a9c5-0000f80367c1")

	ObjectGuidUser               = uuid.UUID{0xbf, 0x96, 0x7a, 0xba, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidComputer           = uuid.UUID{0xbf, 0x96, 0x7a, 0x86, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidGroup              = uuid.UUID{0xbf, 0x96, 0x7a, 0x9c, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidDomain             = uuid.UUID{0x19, 0x19, 0x5a, 0x5a, 0x6d, 0xa0, 0x11, 0xd0, 0xaf, 0xd3, 0x00, 0xc0, 0x4f, 0xd9, 0x30, 0xc9}
	ObjectGuidGPO                = uuid.UUID{0xf3, 0x0e, 0x3b, 0xc2, 0x9f, 0xf0, 0x11, 0xd1, 0xb6, 0x03, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	ObjectGuidOU                 = uuid.UUID{0xbf, 0x96, 0x7a, 0xa5, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidAttributeSchema, _ = uuid.FromString("{BF967A80-0DE6-11D0-A285-00AA003049E2}")

	AdministratorsSID, _           = windowssecurity.SIDFromString("S-1-5-32-544")
	BackupOperatorsSID, _          = windowssecurity.SIDFromString("S-1-5-32-551")
	PrintOperatorsSID, _           = windowssecurity.SIDFromString("S-1-5-32-550")
	ServerOperatorsSID, _          = windowssecurity.SIDFromString("S-1-5-32-549")
	EnterpriseDomainControllers, _ = windowssecurity.SIDFromString("S-1-5-9")

	GPLinkCache = engine.NewAttribute("gpLinkCache")

	PwnPublishesCertificateTemplate = engine.NewPwn("PublishCertTmpl")

	NetBIOSName = engine.NewAttribute("nETBIOSName")
	NCName      = engine.NewAttribute("nCName")
)

var warnedgpos = make(map[string]struct{})

var lapsguids []uuid.UUID

func init() {
	Loader.AddAnalyzers(

		// It's a Unicorn, dang ...
		// engine.PwnAnalyzer{
		// 	Method: activedirectory.PwnNullDACL,
		// 	ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
		// 		var results []*engine.Object
		// 		sd, err := o.SecurityDescriptor()
		// 		if err != nil {
		// 			return
		// 		}
		// 		if sd.Control&engine.CONTROLFLAG_DACL_PRESENT != 0 || len(sd.DACL.Entries) == 0 {
		// 			results = append(results, ao.FindOrAddAdjacentSID(acl.SID, o))
		// 		}

		// 		return results
		// 	},
		// },

		engine.PwnAnalyzer{
			// Method: activedirectory.PwnReadLAPSPassword,
			Description: "Reading local admin passwords via LAPS",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only if we've picked up some LAPS attribute GUIDs
				if len(lapsguids) == 0 {
					return
				}

				// Only for computers
				if o.Type() != engine.ObjectTypeComputer {
					return
				}
				// ... that has LAPS installed
				if o.Attr(activedirectory.MSmcsAdmPwdExpirationTime).Len() == 0 {
					return
				}
				// Analyze ACL
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					for _, objectGUID := range lapsguids {
						if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_CONTROL_ACCESS, objectGUID, ao) {
							ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnReadLAPSPassword)
						}
					}
				}
			},
		},

		engine.PwnAnalyzer{
			// Method: activedirectory.PwnComputerAffectedByGPO,
			Description: "Computers affected by a GPO",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only for computers, you can't really pwn users this way
				if o.Type() != engine.ObjectTypeComputer {
					return
				}
				// Find all perent containers with GP links
				var hasparent bool
				p := o

				// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/5c7ecdad-469f-4b30-94b3-450b7fff868f
				allowEnforcedGPOsOnly := false
				for {
					newparent := p.Parent()
					var foundparent bool
					if newparent != nil && newparent.DN() != "" && strings.HasSuffix(p.DN(), newparent.DN()) {
						p = newparent
						foundparent = true
					}
					if !foundparent {
						// Fall back to old slow method of looking at DNs
						p, hasparent = ao.DistinguishedParent(p)
						if !hasparent {
							break
						}
					}

					var gpcachelinks engine.AttributeValues
					var found bool
					if gpcachelinks, found = p.Get(GPLinkCache); !found {
						// the hard way
						gpcachelinks = engine.NoValues{} // We assume there is nothing

						gplinks := strings.Trim(p.OneAttrString(activedirectory.GPLink), " ")
						if len(gplinks) != 0 {
							// log.Debug().Msgf("GPlink for %v on container %v: %v", o.DN(), p.DN(), gplinks)
							if !strings.HasPrefix(gplinks, "[") || !strings.HasSuffix(gplinks, "]") {
								log.Error().Msgf("Error parsing gplink on %v: %v", o.DN(), gplinks)
							} else {
								links := strings.Split(gplinks[1:len(gplinks)-1], "][")

								var collecteddata engine.AttributeValueSlice
								for _, link := range links {
									linkinfo := strings.Split(link, ";")
									if len(linkinfo) != 2 {
										log.Error().Msgf("Error parsing gplink on %v: %v", o.DN(), gplinks)
										continue
									}
									linkedgpodn := linkinfo[0][7:] // strip LDAP:// prefix and link to this

									gpo, found := ao.Find(engine.DistinguishedName, engine.AttributeValueString(linkedgpodn))
									if !found {
										if _, warned := warnedgpos[linkedgpodn]; !warned {
											warnedgpos[linkedgpodn] = struct{}{}
											log.Warn().Msgf("Object linked to GPO that is not found %v: %v", o.DN(), linkedgpodn)
										}
									} else {
										linktype, _ := strconv.ParseInt(linkinfo[1], 10, 64)
										collecteddata = append(collecteddata, engine.AttributeValueObject{
											Object: gpo,
										}, engine.AttributeValueInt(linktype))
									}
								}
								gpcachelinks = collecteddata
							}
						}
						p.Set(GPLinkCache, gpcachelinks)
					}

					// cached or generated - pairwise pointer to gpo object and int
					gplinkslice := gpcachelinks.Slice()
					for i := 0; i < gpcachelinks.Len(); i += 2 {
						gpo := gplinkslice[i].Raw().(*engine.Object)
						gpLinkOptions := gplinkslice[i+1].Raw().(int64)
						// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18
						if gpLinkOptions&0x01 != 0 {
							// GPO link is disabled
							continue
						}
						if allowEnforcedGPOsOnly && gpLinkOptions&0x02 == 0 {
							// Enforcement required, but this is not an enforced GPO
							continue
						}
						gpo.Pwns(o, activedirectory.PwnAffectedByGPO)
					}

					gpoptions := p.OneAttrString(activedirectory.GPOptions)
					if gpoptions == "1" {
						// inheritance is blocked, so let's not forget that when moving up
						allowEnforcedGPOsOnly = true
					}
				}
			},
		},

		engine.PwnAnalyzer{
			// Method: activedirectory.PwnGPOMachineConfigPartOfGPO,
			Description: "Machine configurations that are part of a GPO",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				if o.Type() != engine.ObjectTypeContainer || o.OneAttrString(engine.Name) != "Machine" {
					return
				}
				// Only for computers, you can't really pwn users this way
				p, hasparent := ao.DistinguishedParent(o)
				if !hasparent || p.Type() != engine.ObjectTypeGroupPolicyContainer {
					return
				}
				p.Pwns(o, activedirectory.PartOfGPO)
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnGPOUserConfigPartOfGPO,
			Description: "User configurations that are part of a GPO",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				if o.Type() != engine.ObjectTypeContainer || o.OneAttrString(engine.Name) != "User" {
					return
				}
				// Only for users, you can't really pwn users this way
				p, hasparent := ao.DistinguishedParent(o)
				if !hasparent || p.Type() != engine.ObjectTypeGroupPolicyContainer {
					return
				}
				p.Pwns(o, activedirectory.PartOfGPO)
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnACLContainsDeny,
			Description: "Indicator for possible false positives, as the ACL contains DENY entries",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// It's a group
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for _, acl := range sd.DACL.Entries {
					if acl.Type == engine.ACETYPE_ACCESS_DENIED || acl.Type == engine.ACETYPE_ACCESS_DENIED_OBJECT {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnACLContainsDeny) // Not a probability of success, this is just an indicator
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnOwns,
			Description: "Indicator that someone owns an object",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				// https://www.alsid.com/crb_article/kerberos-delegation/
				// --- Citation bloc --- This is generally true, but an exception exists: positioning a Deny for the OWNER RIGHTS SID (S-1-3-4) in an object’s ACE removes the owner’s implicit control of this object’s DACL. ---------------------
				aclhasdeny := false
				for _, ace := range sd.DACL.Entries {
					if ace.Type == engine.ACETYPE_ACCESS_DENIED && ace.SID == windowssecurity.OwnerSID {
						aclhasdeny = true
					}
				}
				if !sd.Owner.IsNull() && !aclhasdeny {
					ao.FindOrAddAdjacentSID(sd.Owner, o).Pwns(o, activedirectory.PwnOwns)
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnGenericAll,
			Description: "Indicator that someone has full permissions on an object",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_GENERIC_ALL, engine.NullGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnGenericAll)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnWriteAll,
			Description: "Indicator that someone can write to all attributes and do all validated writes on an object",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_GENERIC_WRITE, engine.NullGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteAll)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnWritePropertyAll,
			Description: "Indicator that someone can write to all attributes of an object",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, engine.NullGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWritePropertyAll)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnWriteExtendedAll,
			Description: "Indicator that someone do all validated writes on an object",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, engine.NullGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteExtendedAll)
					}
				}
			},
		},
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe IMPORTANT
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnTakeOwnership,
			Description: "Indicator that someone is allowed to take ownership of an object",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_WRITE_OWNER, engine.NullGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnTakeOwnership)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnWriteDACL,
			Description: "Indicator that someone can change permissions on an object",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_WRITE_DACL, engine.NullGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteDACL)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method:      activedirectory.PwnWriteAttributeSecurityGUID,
			Description: `Allows an attacker to modify the attribute security set of an attribute, promoting it to a weaker attribute set (experimental/wrong)`,
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sd, err := o.SecurityDescriptor()
				if o.Type() != engine.ObjectTypeAttributeSchema {
					return
				}
				// FIXME - check for SYSTEM ATTRIBUTES - these can NEVER be changed
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeSecurityGUIDGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteAttributeSecurityGUID) // Experimental, I've never run into this misconfiguration
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnResetPassword,
			Description: "Indicator that a group or user can reset the password of an account",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only users, computers and service accounts
				if o.Type() != engine.ObjectTypeUser && o.Type() != engine.ObjectTypeComputer {
					return
				}
				// Check who can reset the password
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_CONTROL_ACCESS, ResetPwd, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnResetPassword)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			Description: "Indicator that a group or user can read the msDS-ManagedPasswordId for use in MGSA Golden attack",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only managed service accounts
				if o.Type() != engine.ObjectTypeManagedServiceAccount && o.Type() != engine.ObjectTypeGroupManagedServiceAccount {
					return
				}

				// Check who can reset the password
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_READ_PROPERTY, AttributeMSDSManagedPasswordId, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnReadPasswordId)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnHasSPN,
			Description: "Indicator that a user has a ServicePrincipalName and an authenticated user can Kerberoast it",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only computers and users
				if o.Type() != engine.ObjectTypeUser {
					return
				}
				if o.Attr(activedirectory.ServicePrincipalName).Len() > 0 {
					o.SetValues(engine.MetaHasSPN, engine.AttributeValueInt(1))

					AuthenticatedUsers, found := ao.FindMulti(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.AuthenticatedUsersSID))
					if !found {
						log.Error().Msgf("Could not locate Authenticated Users")
						return
					}
					AuthenticatedUsers[0].Pwns(o, activedirectory.PwnHasSPN)
				}
			},
		},

		engine.PwnAnalyzer{
			// Method: activedirectory.PwnHasSPN,
			Description: "Indicator that a user has \"don't require preauth\" and can be kerberoasted",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only users
				if o.Type() != engine.ObjectTypeUser {
					return
				}
				if uac, ok := o.AttrInt(activedirectory.UserAccountControl); ok && uac&engine.UAC_DONT_REQ_PREAUTH != 0 {
					everyone, found := ao.FindMulti(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.EveryoneSID))
					if !found {
						log.Error().Msgf("Could not locate Everyone")
						return
					}
					everyone[0].Pwns(o, activedirectory.PwnDontReqPreauth)
				}
			},
		},

		engine.PwnAnalyzer{
			// Method: activedirectory.PwnWriteSPN, // Same GUID as Validated writes, just a different permission (?)
			Description: "Indicator that a user can change the ServicePrincipalName attribute, and then Kerberoast the account",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only computers and users
				if o.Type() != engine.ObjectTypeUser {
					return
				}
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, ValidateWriteSPN, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteSPN)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnWriteValidatedSPN,
			Description: "Indicator that a user can change the ServicePrincipalName attribute (validate write), and then Kerberoast the account",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only computers and users
				if o.Type() != engine.ObjectTypeUser {
					return
				}
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, ValidateWriteSPN, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteValidatedSPN)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method:      activedirectory.PwnWriteAllowedToAct,
			Description: `Modify the msDS-AllowedToActOnBehalfOfOtherIdentity on a computer to enable any SPN enabled user to impersonate anyone else`,
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only computers
				if o.Type() != engine.ObjectTypeComputer {
					return
				}
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeAllowedToActOnBehalfOfOtherIdentity, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteAllowedToAct) // Success rate?
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnAddMember,
			Description: "Permission to add a member to a group",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only for groups
				if o.Type() != engine.ObjectTypeGroup {
					return
				}
				// It's a group
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeMember, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnAddMember)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnAddMemberGroupAttr,
			Description: "Permission to add a member to a group (via attribute set)",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only for groups
				if o.Type() != engine.ObjectTypeGroup {
					return
				}
				// It's a group
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeSetGroupMembership, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnAddMemberGroupAttr)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			Description: "Permission to add yourself to a group",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only for groups
				if o.Type() != engine.ObjectTypeGroup {
					return
				}
				// It's a group
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, ValidateWriteSelfMembership, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnAddSelfMember)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnReadMSAPassword,
			Description: "Allows someone to read a password of a managed service account",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				msasds := o.AttrString(activedirectory.MSDSGroupMSAMembership)
				for _, msasd := range msasds {
					sd, err := engine.ParseSecurityDescriptor([]byte(msasd))
					if err == nil {
						for _, acl := range sd.DACL.Entries {
							if acl.Type == engine.ACETYPE_ACCESS_ALLOWED {
								ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnReadMSAPassword)
							}
						}
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method:      activedirectory.PwnWriteAltSecurityIdentities,
			Description: "Allows an attacker to define a certificate that can be used to authenticate as the user",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only for users
				if o.Type() != engine.ObjectTypeUser {
					return
				}
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeAltSecurityIdentitiesGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteAltSecurityIdentities)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method:      activedirectory.PwnWriteProfilePath,
			Description: "Change user profile path (allows an attacker to trigger a user auth against an attacker controlled UNC path)",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only for users
				if o.Type() != engine.ObjectTypeUser {
					return
				}
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeProfilePathGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteProfilePath)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method:      activedirectory.PwnWriteScriptPath,
			Description: "Change user script path (allows an attacker to trigger a user auth against an attacker controlled UNC path)",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only for users
				if o.Type() != engine.ObjectTypeUser {
					return
				}
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeScriptPathGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteScriptPath)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnHasMSA,
			Description: "Indicates that the object has a service account in use",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				msas := o.Attr(activedirectory.MSDSHostServiceAccount).Slice()
				for _, dn := range msas {
					if targetmsa, found := ao.Find(engine.DistinguishedName, dn); found {
						o.Pwns(targetmsa, activedirectory.PwnHasMSA)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnWriteKeyCredentialLink,
			Description: "Allows you to write your own cert to keyCredentialLink, and then auth as that user (no password reset needed)",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// Only for groups
				if o.Type() != engine.ObjectTypeUser && o.Type() != engine.ObjectTypeComputer {
					return
				}
				// It's a group
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeMSDSKeyCredentialLink, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnWriteKeyCredentialLink)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnSIDHistoryEquality,
			Description: "Indicates that object has a SID History attribute pointing to the other object, making them the 'same' permission wise",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				sids := o.Attr(activedirectory.SIDHistory).Slice()
				for _, sidval := range sids {
					if sid, ok := sidval.Raw().(windowssecurity.SID); ok {
						target := ao.FindOrAddAdjacentSID(sid, o)
						o.Pwns(target, activedirectory.PwnSIDHistoryEquality)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			// Method: activedirectory.PwnAllExtendedRights,
			Description: "Indicates that you have all extended rights",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				// It's a group
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_CONTROL_ACCESS, engine.NullGUID, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnAllExtendedRights)
					}
				}
			},
		},
		engine.PwnAnalyzer{
			Description: "Certificate service publishes Certificate Template",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				if o.Type() != engine.ObjectTypePKIEnrollmentService {
					return
				}
				for _, cts := range o.AttrString(engine.A("certificateTemplates")) {
					for _, ct := range cts {
						templates, _ := ao.FindMulti(engine.Name, engine.AttributeValueString(ct))
						for _, template := range templates {
							if template.Type() == engine.ObjectTypeCertificateTemplate {
								o.Pwns(template, PwnPublishesCertificateTemplate)
							}
						}
					}
				}
			},
		},
		engine.PwnAnalyzer{
			Description: "Permission to enroll into a certificate template",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				if o.Type() != engine.ObjectTypeCertificateTemplate {
					return
				}
				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightCertificateEnroll, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnCertificateEnroll)
					}
				}
			},
		},

		engine.PwnAnalyzer{
			Description: "Permissions on DomainDNS objects leading to DCsync attacks",
			ObjectAnalyzer: func(o *engine.Object, ao *engine.Objects) {
				if o.Type() != engine.ObjectTypeDomainDNS {
					return
				}
				if !o.HasAttr(activedirectory.SystemFlags) {
					return
				}

				sd, err := o.SecurityDescriptor()
				if err != nil {
					return
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationSyncronize, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnDSReplicationSyncronize)
					}
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChanges, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnDSReplicationGetChanges)
					}
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesAll, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnDSReplicationGetChangesAll)
					}
					if sd.DACL.AllowObjectClass(index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesInFilteredSet, ao) {
						ao.FindOrAddAdjacentSID(acl.SID, o).Pwns(o, activedirectory.PwnDSReplicationGetChangesInFilteredSet)
					}
				}

				// Add the DCsync combination flag
				for p, methods := range o.PwnableBy {
					if methods.IsSet(activedirectory.PwnDSReplicationGetChanges) && methods.IsSet(activedirectory.PwnDSReplicationGetChangesAll) {
						// DCsync attack WOT WOT
						p.Pwns(o, activedirectory.PwnDCsync)
					}
				}
			},
		},
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Ensure everyone has a family
		for _, o := range ao.Slice() {

			if o.Parent() != nil {
				continue
			}

			if o == ao.Root() {
				continue
			}

			if parent, found := ao.DistinguishedParent(o); found {
				o.ChildOf(parent)
			} else {
				dn := o.DN()
				if o.Type() == engine.ObjectTypeDomainDNS && len(dn) > 3 && strings.EqualFold("dc=", dn[:3]) {
					// Top of some AD we think, hook to top of browsable tree
					o.ChildOf(ao.Root())
					continue
				}
				log.Debug().Msgf("AD object %v (%v) has no parent :-(", o.Label(), o.DN())
			}
		}
	},
		"applying parent/child relationships",
		engine.BeforeMergeHigh)

	Loader.AddProcessor(func(ao *engine.Objects) {
		type domaininfo struct {
			suffix string
			name   string
		}
		var domains []domaininfo

		results, found := ao.FindMulti(engine.ObjectClass, engine.AttributeValueString("crossRef"))

		if !found {
			log.Error().Msg("No domainDNS object found, can't apply DownLevelLogonName to objects")
			return
		}

		for _, o := range results {
			// Store domain -> netbios name in array for later
			dn := o.OneAttrString(NCName)
			netbiosname := o.OneAttrString(NetBIOSName)

			if dn == "" || netbiosname == "" {
				log.Warn().Msgf("Cross reference object %v has no NCName or NetBIOSName", o.DN())
				continue
			}

			domains = append(domains, domaininfo{
				suffix: dn,
				name:   netbiosname,
			})
		}

		// Sort the domains so we match on longest first
		sort.Slice(domains, func(i, j int) bool {
			// Less is More - so we sort in reverse order
			return len(domains[i].suffix) > len(domains[j].suffix)
		})

		// Apply DownLevelLogonName to relevant objects
		for _, o := range ao.Slice() {
			if !o.HasAttr(engine.SAMAccountName) {
				continue
			}
			dn := o.DN()
			for _, domaininfo := range domains {
				if strings.HasSuffix(dn, domaininfo.suffix) {
					o.SetValues(engine.DownLevelLogonName, engine.AttributeValueString(domaininfo.name+"\\"+o.OneAttrString(engine.SAMAccountName)))
					break
				}
			}
		}

		ao.DropIndex(engine.DownLevelLogonName)
	},
		"applying DownLevelLogonName attribute",
		engine.BeforeMergeLow)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Add domain part attribute from distinguished name to objects
		for _, o := range ao.Slice() {
			// Only objects with a DistinguishedName
			if o.DN() == "" {
				continue
			}

			if o.HasAttr(engine.DomainPart) {
				continue
			}

			parts := strings.Split(o.DN(), ",")
			lastpart := -1

			for i := len(parts) - 1; i >= 0; i-- {
				part := parts[i]
				if len(part) < 3 || !strings.EqualFold("dc=", part[:3]) {
					break
				}
				lastpart = i
			}

			if lastpart != -1 {
				o.SetValues(engine.DomainPart, engine.AttributeValueString(strings.Join(parts[lastpart:], ",")))
			}
		}
	},
		"applying domain part attribute",
		engine.BeforeMergeLow)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Find all the AdminSDHolder containers
		for _, adminsdholder := range ao.Filter(func(o *engine.Object) bool {
			return strings.HasPrefix(o.OneAttrString(engine.DistinguishedName), "CN=AdminSDHolder,CN=System,")
		}).Slice() {
			// We found it - so we know it can change ACLs of some objects
			domainpart := adminsdholder.OneAttrString(engine.DomainPart)

			// Are some groups excluded?
			excluded_mask := 0

			// Find dsHeuristics, this defines groups EXCLUDED From AdminSDHolder application
			// https://social.technet.microsoft.com/wiki/contents/articles/22331.adminsdholder-protected-groups-and-security-descriptor-propagator.aspx#What_is_a_protected_group
			if ds, found := ao.Find(engine.DistinguishedName, engine.AttributeValueString("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+domainpart)); found {
				excluded := ds.OneAttrString(activedirectory.DsHeuristics)
				if len(excluded) >= 16 {
					excluded_mask = strings.Index("0123456789ABCDEF", strings.ToUpper(string(excluded[15])))
				}
			}

			for _, o := range ao.Filter(func(o *engine.Object) bool {
				// Check if object is a group
				if o.Type() != engine.ObjectTypeGroup {
					return false
				}

				// Only this "local" AD (for multi domain analysis)
				if o.OneAttrString(engine.DomainPart) != domainpart {
					return false
				}
				return true
			}).Slice() {

				grpsid := o.SID()
				if grpsid.IsNull() {
					continue
				}

				switch grpsid.RID() {
				case DOMAIN_USER_RID_ADMIN:
				case DOMAIN_USER_RID_KRBTGT:
				case DOMAIN_GROUP_RID_ADMINS:
				case DOMAIN_GROUP_RID_CONTROLLERS:
				case DOMAIN_GROUP_RID_SCHEMA_ADMINS:
				case DOMAIN_GROUP_RID_ENTERPRISE_ADMINS:
				case DOMAIN_GROUP_RID_READONLY_CONTROLLERS:
				case DOMAIN_ALIAS_RID_ADMINS:
				case DOMAIN_ALIAS_RID_ACCOUNT_OPS:
					if excluded_mask&1 != 0 {
						continue
					}
				case DOMAIN_ALIAS_RID_SYSTEM_OPS:
					if excluded_mask&2 != 0 {
						continue
					}
				case DOMAIN_ALIAS_RID_PRINT_OPS:
					if excluded_mask&4 != 0 {
						continue
					}
				case DOMAIN_ALIAS_RID_BACKUP_OPS:
					if excluded_mask&8 != 0 {
						continue
					}
				case DOMAIN_ALIAS_RID_REPLICATOR:
				default:
					// Not a protected group
					continue
				}

				// Only domain groups
				if grpsid.Component(2) != 21 && grpsid.Component(2) != 32 {
					log.Debug().Msgf("RID match but not domain object for %v with SID %v", o.OneAttrString(engine.DistinguishedName), o.SID().String())
					continue
				}

				adminsdholder.Pwns(o, activedirectory.PwnOverwritesACL)
				dm := o.Members(false)
				idm := o.Members(true)
				_ = dm
				_ = idm
				for _, member := range o.Members(true) {
					adminsdholder.Pwns(member, activedirectory.PwnOverwritesACL)
				}
			}
		}
	},
		"AdminSDHolder rights propagation indicator",
		engine.BeforeMerge)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Add our known SIDs if they're missing
		for sid, name := range windowssecurity.KnownSIDs {
			binsid, err := windowssecurity.SIDFromString(sid)
			if err != nil {
				log.Fatal().Msgf("Problem parsing SID %v", sid)
			}
			if fo := FindWellKnown(ao, binsid); fo == nil {
				dn := "CN=" + name + ",CN=microsoft-builtin"
				log.Debug().Msgf("Adding missing well known SID %v (%v) as %v", name, sid, dn)
				ao.Add(engine.NewObject(
					engine.DistinguishedName, engine.AttributeValueString(dn),
					engine.Name, engine.AttributeValueString(name),
					engine.ObjectSid, engine.AttributeValueSID(binsid),
					engine.ObjectClass, engine.AttributeValueString("person"), engine.AttributeValueString("user"), engine.AttributeValueString("top"),
					engine.ObjectCategorySimple, engine.AttributeValueString("Group"),
				))
			}
		}
	},
		"missing well-known SIDs",
		engine.BeforeMerge,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Generate member of chains
		processbar := progressbar.NewOptions(int(len(ao.Slice())),
			progressbar.OptionSetDescription("Processing objects..."),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetItsString("objects"),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
			progressbar.OptionThrottle(time.Second*1),
		)

		everyonesid, _ := windowssecurity.SIDFromString("S-1-1-0")
		everyone := FindWellKnown(ao, everyonesid)
		if everyone == nil {
			log.Fatal().Msgf("Could not locate Everyone, aborting - this should at least have been added during earlier preprocessing")
		}

		authenticateduserssid, _ := windowssecurity.SIDFromString("S-1-5-11")
		authenticatedusers := FindWellKnown(ao, authenticateduserssid)
		if authenticatedusers == nil {
			log.Fatal().Msgf("Could not locate Authenticated Users, aborting - this should at least have been added during earlier preprocessing")
		}

		for _, object := range ao.Slice() {
			processbar.Add(1)

			// We'll put the ObjectClass UUIDs in a synthetic attribute, so we can look it up later quickly (and without access to Objects)
			objectclasses := object.Attr(engine.ObjectClass).Slice()
			if len(objectclasses) > 0 {
				var guids []engine.AttributeValue
				for _, class := range objectclasses {
					if oto, found := ao.Find(engine.LDAPDisplayName, class); found {
						if _, ok := oto.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID); !ok {
							log.Debug().Msgf("%v", oto)
							log.Fatal().Msgf("Sorry, could not translate SchemaIDGUID for class %v - I need a Schema to work properly", class)
						} else {
							guids = append(guids, oto.OneAttr(activedirectory.SchemaIDGUID))
						}
					}
				}
				if len(guids) > 0 {
					object.Set(engine.ObjectClassGUIDs, engine.AttributeValueSlice(guids))
				}
			}

			var objectcategoryguid engine.AttributeValues
			objectcategoryguid = engine.AttributeValueSlice{engine.AttributeValueGUID(engine.UnknownGUID)}
			typedn := object.OneAttr(engine.ObjectCategory)

			// Does it have one, and does it have a comma, then we're assuming it's not just something we invented
			if typedn != nil && strings.Contains(typedn.String(), ",") {
				if oto, found := ao.Find(engine.DistinguishedName, typedn); found {
					if _, ok := oto.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID); ok {
						objectcategoryguid = oto.Attr(activedirectory.SchemaIDGUID)
					} else {
						log.Error().Msgf("Sorry, could not translate SchemaIDGUID for %v", typedn)
					}
				} else {
					log.Error().Msgf("Sorry, could not resolve object category %v, perhaps you didn't get a dump of the schema?", typedn)
				}
			}
			object.Set(engine.ObjectCategoryGUID, objectcategoryguid)

			if rid, ok := object.AttrInt(activedirectory.PrimaryGroupID); ok {
				sid := object.SID()
				if len(sid) > 8 {
					sidbytes := []byte(sid)
					binary.LittleEndian.PutUint32(sidbytes[len(sid)-4:], uint32(rid))
					primarygroup := ao.FindOrAddAdjacentSID(windowssecurity.SID(sidbytes), object)
					primarygroup.AddMember(object)
				}
			}

			// Crude special handling for Everyone and Authenticated Users
			if object.Type() == engine.ObjectTypeUser || object.Type() == engine.ObjectTypeComputer || object.Type() == engine.ObjectTypeManagedServiceAccount || object.Type() == engine.ObjectTypeForeignSecurityPrincipal || object.Type() == engine.ObjectTypeGroupManagedServiceAccount {
				everyone.AddMember(object)
				authenticatedusers.AddMember(object)
			}

			if lastlogon, ok := object.AttrTimestamp(activedirectory.LastLogonTimestamp); ok {
				object.SetValues(engine.MetaLastLoginAge, engine.AttributeValueInt(int(time.Since(lastlogon)/time.Hour)))
			}
			if passwordlastset, ok := object.AttrTimestamp(activedirectory.PwdLastSet); ok {
				object.SetValues(engine.MetaPasswordAge, engine.AttributeValueInt(int(time.Since(passwordlastset)/time.Hour)))
			}
			if strings.Contains(strings.ToLower(object.OneAttrString(activedirectory.OperatingSystem)), "linux") {
				object.SetValues(engine.MetaLinux, engine.AttributeValueInt(1))
			}
			if strings.Contains(strings.ToLower(object.OneAttrString(activedirectory.OperatingSystem)), "windows") {
				object.SetValues(engine.MetaWindows, engine.AttributeValueInt(1))
			}
			if object.Attr(activedirectory.MSmcsAdmPwdExpirationTime).Len() > 0 {
				object.SetValues(engine.MetaLAPSInstalled, engine.AttributeValueInt(1))
			}
			if uac, ok := object.AttrInt(activedirectory.UserAccountControl); ok {
				if uac&engine.UAC_TRUSTED_FOR_DELEGATION != 0 {
					object.SetValues(engine.MetaUnconstrainedDelegation, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
					object.SetValues(engine.MetaConstrainedDelegation, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_NOT_DELEGATED != 0 {
					log.Debug().Msgf("%v has can't be used as delegation", object.DN())
				}
				if uac&engine.UAC_WORKSTATION_TRUST_ACCOUNT != 0 {
					object.SetValues(engine.MetaWorkstation, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_SERVER_TRUST_ACCOUNT != 0 {
					object.SetValues(engine.MetaServer, engine.AttributeValueInt(1))

					// All DCs are members of Enterprise Domain Controllers
					object.Pwns(ao.FindOrAddAdjacentSID(EnterpriseDomainControllers, object), activedirectory.PwnMemberOfGroup)
				}
				if uac&engine.UAC_ACCOUNTDISABLE != 0 {
					object.SetValues(engine.MetaAccountDisabled, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_PASSWD_CANT_CHANGE != 0 {
					object.SetValues(engine.MetaPasswordCantChange, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_DONT_EXPIRE_PASSWORD != 0 {
					object.SetValues(engine.MetaPasswordNoExpire, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_PASSWD_NOTREQD != 0 {
					object.SetValues(engine.MetaPasswordNotRequired, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_SERVER_TRUST_ACCOUNT != 0 {
					// Domain Controller
					domainPart := object.OneAttr(engine.DomainPart)
					if domainPart == nil {
						log.Fatal().Msgf("DomainController %v has no DomainPart attribute", object.DN())
					}

					if administrators, found := ao.FindTwo(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.AdministratorsSID),
						engine.DomainPart, domainPart); found {
						administrators.Pwns(object, activedirectory.PwnLocalAdminRights)
					} else {
						log.Warn().Msgf("Could not find Administrators group for %v", object.DN())
					}

					if remotedesktopusers, found := ao.FindTwo(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.RemoteDesktopUsersSID),
						engine.DomainPart, domainPart); found {
						remotedesktopusers.Pwns(object, activedirectory.PwnLocalRDPRights)
					} else {
						log.Warn().Msgf("Could not find Remote Desktop Users group for %v", object.DN())
					}

					if distributeddcomusers, found := ao.FindTwo(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.DCOMUsersSID),
						engine.DomainPart, domainPart); found {
						distributeddcomusers.Pwns(object, activedirectory.PwnLocalDCOMRights)
					} else {
						log.Warn().Msgf("Could not find DCOM Users group for %v", object.DN())
					}
				}
			}

			if object.Type() == engine.ObjectTypeTrust {
				// http://www.frickelsoft.net/blog/?p=211
				var direction string
				dir, _ := object.AttrInt(activedirectory.TrustDirection)
				switch dir {
				case 0:
					direction = "disabled"
				case 1:
					direction = "incoming"
				case 2:
					direction = "outgoing"
				case 3:
					direction = "bidirectional"
				}
				attr, _ := object.AttrInt(activedirectory.TrustAttributes)
				log.Info().Msgf("Domain has a %v trust with %v", direction, object.OneAttr(activedirectory.TrustPartner))
				if dir&2 != 0 && attr&0x08 != 0 && attr&0x40 != 0 {
					log.Info().Msgf("SID filtering is not enabled, so pwn %v and pwn this AD too", object.OneAttr(activedirectory.TrustPartner))
				}
			}

			if object.HasAttrValue(engine.ObjectClass, engine.AttributeValueString("attributeSchema")) {
				if objectGUID, ok := object.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID); ok {

					// engine.AllSchemaAttributes[objectGUID] = object
					switch object.OneAttrString(engine.Name) {
					case "ms-Mcs-AdmPwd":
						log.Info().Msg("Detected LAPS schema extension, adding this to LAPS analyzer")
						lapsguids = append(lapsguids, objectGUID)
					}
				}
			} /* else if object.HasAttrValue(engine.ObjectClass, "classSchema") {
				if u, ok := object.OneAttrRaw(engine.SchemaIDGUID).(uuid.UUID); ok {
					// log.Debug().Msgf("Adding schema class %v %v", u, object.OneAttr(Name))
					engine.AllSchemaClasses[u] = object
				}
			}*/
		}
		processbar.Finish()
	},
		"Active Directory objects and metadata",
		engine.BeforeMerge)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, object := range ao.Slice() {
			if object.HasAttrValue(engine.Name, engine.AttributeValueString("Protected Users")) && object.SID().RID() == 525 { // "Protected Users"
				for _, member := range object.Members(true) {
					member.SetValues(engine.MetaProtectedUser, engine.AttributeValueInt(1))
				}
			}
		}
	},
		"Protected users meta attribute",
		engine.BeforeMerge,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Find all the DomainDNS objects, and find the domain object
		for _, domaindns := range ao.Filter(func(o *engine.Object) bool {
			return o.Type() == engine.ObjectTypeDomainDNS && o.HasAttr(engine.ObjectSid)
		}).Slice() {
			ourDomainDN := domaindns.DN()
			ourDomainSid := domaindns.SID()

			for _, o := range ao.Slice() {
				if o.HasAttr(engine.ObjectSid) && o.SID().Component(2) == 21 && !o.HasAttr(engine.DistinguishedName) {
					// An unknown SID, is it ours or from another domain?
					if o.SID().StripRID() == ourDomainSid {
						log.Warn().Msgf("Found a 'lost' local SID object %v, but not taking action (don't know where to place it). This will affect your analysis results, try dumping as Domain Admin!", o.SID())
					} else {
						log.Debug().Msgf("Found a 'lost' foreign SID object %v, adding it as a synthetic Foreign-Security-Principal", o.SID())
						o.SetFlex(
							engine.DistinguishedName, engine.AttributeValueString(o.SID().String()+",CN=ForeignSecurityPrincipals,"+ourDomainDN),
							engine.ObjectCategorySimple, "Foreign-Security-Principal",
							engine.MetaDataSource, "Autogenerated",
						)
					}
				}
			}
		}

	},
		"Creation of synthetic Foreign-Security-Principal objects",
		engine.BeforeMerge)

	Loader.AddProcessor(func(ao *engine.Objects) {
		creatorowner, found := ao.Find(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.CreatorOwnerSID))
		if !found {
			log.Warn().Msg("Could not find Creator Owner Well Known SID. Not doing post-merge fixup")
			return
		}

		for target, methods := range creatorowner.CanPwn {
			// ACL grants CreatorOwnerSID something - so let's find the owner and give them the permissions
			if sd, err := target.SecurityDescriptor(); err == nil {
				if sd.Owner != windowssecurity.BlankSID {
					if realowners, found := ao.FindMulti(engine.ObjectSid, engine.AttributeValueSID(sd.Owner)); found {
						for _, realo := range realowners {
							if realo.Type() == engine.ObjectTypeForeignSecurityPrincipal || realo.Type() == engine.ObjectTypeOther {
								// Skip this
								continue
							}

							// Link real target
							realo.CanPwn[target] = realo.CanPwn[target].Merge(methods)
							target.PwnableBy[realo] = target.PwnableBy[realo].Merge(methods)

							// Unlink creatorowner
							delete(creatorowner.CanPwn, target)
							delete(target.PwnableBy, creatorowner)
						}
					}
				}
			}
		}
	},
		"CreatorOwnerSID resolution fixup",
		engine.BeforeMerge,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, object := range ao.Slice() {
			// Object that is member of something
			for _, memberof := range object.Attr(activedirectory.MemberOf).Slice() {
				group, found := ao.Find(engine.DistinguishedName, memberof)
				if !found {
					var sid engine.AttributeValueSID
					if stringsid, _, found := strings.Cut(memberof.String(), ",CN=ForeignSecurityPrincipals,"); found {
						// We can figure out what the SID is
						if c, err := windowssecurity.SIDFromString(stringsid); err == nil {
							sid = engine.AttributeValueSID(c)
						}
						log.Info().Msgf("Missing Foreign-Security-Principal: %v is a member of %v, which is not found - adding enhanced synthetic group", object.DN(), memberof)
					} else {
						log.Warn().Msgf("Possible hardening? %v is a member of %v, which is not found - adding synthetic group. Your analysis will be degraded, try dumping with Domain Admin rights.", object.DN(), memberof)
					}
					group = engine.NewObject(
						engine.IgnoreBlanks,
						engine.DistinguishedName, memberof,
						engine.ObjectCategorySimple, engine.AttributeValueString("Group"),
						engine.ObjectClass, engine.AttributeValueString("top"), engine.AttributeValueString("group"),
						engine.Name, engine.AttributeValueString("Synthetic group "+memberof.String()),
						engine.Description, engine.AttributeValueString("Synthetic group"),
						engine.ObjectSid, sid,
						engine.MetaDataSource, engine.AttributeValueString("Autogenerated"),
					)
					ao.Add(group)
				}
				group.AddMember(object)
			}

			// Group that contains members
			for _, member := range object.Attr(activedirectory.Member).Slice() {
				memberobject, found := ao.Find(engine.DistinguishedName, member)
				if !found {
					var sid engine.AttributeValueSID
					var category string
					if stringsid, _, found := strings.Cut(member.String(), ",CN=ForeignSecurityPrincipals,"); found {
						// We can figure out what the SID is
						if c, err := windowssecurity.SIDFromString(stringsid); err == nil {
							sid = engine.AttributeValueSID(c)
							category = "Foreign-Security-Principal"
						}
						log.Info().Msgf("Missing Foreign-Security-Principal: %v is a member of %v, which is not found - adding enhanced synthetic group", object.DN(), member)
					} else {
						log.Warn().Msgf("Possible hardening? %v is a member of %v, which is not found - adding synthetic group. Your analysis will be degraded, try dumping with Domain Admin rights.", object.DN(), member)
					}
					memberobject = engine.NewObject(
						engine.IgnoreBlanks,
						engine.DistinguishedName, member,
						engine.ObjectCategorySimple, category,
						engine.ObjectSid, sid,
						engine.MetaDataSource, "Autogenerated",
					)
					ao.Add(memberobject)
				}
				object.AddMember(memberobject)
			}

			for _, member := range object.Members(false) {
				member.Pwns(object, activedirectory.PwnMemberOfGroup)
			}
		}
	},
		"MemberOf and Member resolution",
		engine.AfterMerge,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, foreign := range ao.Filter(func(o *engine.Object) bool {
			return o.Type() == engine.ObjectTypeForeignSecurityPrincipal
		}).Slice() {
			sid := foreign.SID()
			if sid.IsNull() {
				log.Error().Msgf("Found a foreign security principal with no SID %v", foreign.Label())
				continue
			}
			if sid.Component(2) == 21 {
				if sources, found := ao.FindMulti(engine.ObjectSid, engine.AttributeValueSID(sid)); found {
					for _, source := range sources {
						if source.Type() != engine.ObjectTypeForeignSecurityPrincipal {
							source.PwnsEx(foreign, activedirectory.PwnForeignIdentity, true)
						}
					}
				}
			} else {
				log.Warn().Msgf("Found a foreign security principal %v with an non type 21 SID %v", foreign.DN(), sid.String())
			}
		}
	}, "Link foreign security principals to their native objects",
		engine.AfterMerge,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		var warnlines int
		for _, gpo := range ao.Filter(func(o *engine.Object) bool {
			return o.Type() == engine.ObjectTypeGroupPolicyContainer
		}).Slice() {
			for group, methods := range gpo.PwnableBy {

				groupname := group.OneAttrString(engine.SAMAccountName)
				if strings.Contains(groupname, "%") {
					// Lowercase for ease
					groupname := strings.ToLower(groupname)

					// It has some sort of % variable in it, let's go
					for affected, amethods := range gpo.CanPwn {
						if amethods.IsSet(activedirectory.PwnAffectedByGPO) && affected.Type() == engine.ObjectTypeComputer {
							netbiosdomain, computername, found := strings.Cut(affected.OneAttrString(engine.DownLevelLogonName), "\\")
							if !found {
								log.Error().Msgf("Could not parse downlevel logon name %v", affected.OneAttrString(engine.DownLevelLogonName))
								continue
							}
							computername = strings.TrimRight(computername, "$")

							realgroup := groupname
							realgroup = strings.Replace(realgroup, "%computername%", computername, -1)
							realgroup = strings.Replace(realgroup, "%domainname%", netbiosdomain, -1)
							realgroup = strings.Replace(realgroup, "%domain%", netbiosdomain, -1)

							var targetgroups []*engine.Object

							if !strings.Contains(realgroup, "\\") {
								realgroup = netbiosdomain + "\\" + realgroup
							}
							targetgroups, _ = ao.FindMulti(
								engine.DownLevelLogonName, engine.AttributeValueString(realgroup),
							)

							if len(targetgroups) == 0 {
								if warnlines < 10 {
									log.Warn().Msgf("Could not find group %v", realgroup)
								}
								warnlines++
							} else if len(targetgroups) == 1 {
								for _, method := range methods.Methods() {
									targetgroups[0].PwnsEx(affected, method, true)
								}
							} else {
								log.Warn().Msgf("Found multiple groups for %v: %v", realgroup, targetgroups)
								for _, targetgroup := range targetgroups {
									log.Warn().Msgf("Target: %v", targetgroup.DN())
								}
							}
						}
					}
				}

			}
		}
		if warnlines > 0 {
			log.Warn().Msgf("%v groups could not be resolved, this could affect analysis results", warnlines)
		}

	}, "Resolve expanding group names to real names from GPOs",
		engine.AfterMerge,
	)
}
