package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"

	"github.com/lkarlslund/adalanche/modules/collector"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var (
	LocalMachineSID = A("LocalMachineSID")
)

func importCollectorFile(path string, objs *Objects) error {
	// Import it
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return errors.Wrap(err, "Problem reading collector file")
	}
	var cinfo collector.Info
	err = json.Unmarshal(raw, &cinfo)
	if err != nil {
		return errors.Wrap(err, "Problem unmarshalling data from JSON file")
	}

	//			if !strings.EqualFold(objs.Domain, cinfo.Machine.Domain) {
	//				return nil // Machine is domain joined, but not to this domain!? Ignore for now
	//			}

	if !cinfo.Machine.IsDomainJoined {
		log.Info().Msgf("Not importing non domain joined machine %v", cinfo.Machine.Name)
		return nil
	}

	// CHeck that the computer is a member of this domain
	// ... NETBIOS FIXME

	// find computer object by SID
	var computerobject *Object
	var found bool
	if cinfo.Machine.ComputerDomainSID != "" {
		csid, err := SIDFromString(cinfo.Machine.ComputerDomainSID)
		if err == nil {
			if computerobject, found = objs.Find(ObjectSid, AttributeValueSID(csid)); !found {
				log.Warn().Msgf("Could not locate machine %v with domain SID %v, falling back to name lookup", cinfo.Machine.Name, cinfo.Machine.ComputerDomainSID)
			}
		}
	}

	// Fallback to looking by machine account name
	if computerobject == nil {
		if computerobject, found = objs.Find(SAMAccountName, AttributeValueString(cinfo.Machine.Name+"$")); !found {
			log.Info().Msgf("Not importing collector data for machine %v - not found in object collection", cinfo.Machine.Name)
			return nil // We didn't find it
		}
	}

	// Save the Info object on the Object, we can use this for presentation later on
	computerobject.collectorinfo = &cinfo

	// See if the machine has a unique SID
	localsid, err := SIDFromString(cinfo.Machine.LocalSID)
	if err != nil {
		localsid, _ = SIDFromString("S-1-5-555-" + strconv.FormatUint(uint64(rand.Int31()), 10) + "-" + strconv.FormatUint(uint64(rand.Int31()), 10) + "-" + strconv.FormatUint(uint64(rand.Int31()), 10))
	}

	if dupe, found := objs.Find(LocalMachineSID, AttributeValueSID(localsid)); found {
		localsid, _ = SIDFromString("S-1-5-555-" + strconv.FormatUint(uint64(rand.Int31()), 10) + "-" + strconv.FormatUint(uint64(rand.Int31()), 10) + "-" + strconv.FormatUint(uint64(rand.Int31()), 10))
		log.Warn().Msgf("Not registering machine %v with real local SID %v, as it already exists as %v, using generated SID %v instead", cinfo.Machine.Name, cinfo.Machine.LocalSID, dupe.OneAttr(SAMAccountName), localsid)
	}
	computerobject.SetAttr(LocalMachineSID, AttributeValueSID(localsid))

	// Add local accounts as synthetic objects

	// If it brings value ... ?

	// Iterate over Groups
	for _, group := range cinfo.Groups {
		groupsid, err := SIDFromString(group.SID)

		if err != nil && group.Name != "SMS Admins" {
			log.Warn().Msgf("Can't convert local group SID %v: %v", group.SID, err)
			continue
		}
		for _, member := range group.Members {
			var membersid SID
			if member.SID != "" {
				membersid, err = SIDFromString(member.SID)
				if err != nil {
					log.Warn().Msgf("Can't convert local group member SID %v: %v", member.SID, err)
					continue
				}
			} else {
				// Some members show up with the SID in the name field FML
				membersid, err = SIDFromString(member.Name)
				if err != nil {
					log.Info().Msgf("Fallback SID translation on %v failed: %v", member.Name, err)
					continue
				}
			}

			if membersid.Component(2) != 21 {
				continue // Not a domain SID, skip it
			}

			if member, found := objs.Find(ObjectSid, AttributeValueSID(membersid)); found {
				switch {
				case group.Name == "SMS Admins":
					member.Pwns(computerobject, PwnLocalSMSAdmins, 50)
				case groupsid == SIDAdministrators:
					member.Pwns(computerobject, PwnLocalAdminRights, 100)
				case groupsid == SIDDCOMUsers:
					member.Pwns(computerobject, PwnLocalDCOMRights, 50)
				case groupsid == SIDRemoteDesktopUsers:
					member.Pwns(computerobject, PwnLocalRDPRights, 30)
				}
			}
		}
	}

	// USERS THAT HAVE SESSIONS ON THE MACHINE ONCE IN WHILE
	for _, login := range cinfo.LoginPopularity.Day {
		usersid, err := SIDFromString(login.SID)
		if err != nil {
			log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a domain SID, skip it
		}
		if user, found := objs.Find(ObjectSid, AttributeValueSID(usersid)); found {
			computerobject.Pwns(user, PwnLocalSessionLastDay, 80)
		}
	}
	for _, login := range cinfo.LoginPopularity.Week {
		usersid, err := SIDFromString(login.SID)
		if err != nil {
			log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a domain SID, skip it
		}
		if user, found := objs.Find(ObjectSid, AttributeValueSID(usersid)); found {
			computerobject.Pwns(user, PwnLocalSessionLastWeek, 30)
		}
	}
	for _, login := range cinfo.LoginPopularity.Month {
		usersid, err := SIDFromString(login.SID)
		if err != nil {
			log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a domain SID, skip it
		}
		if user, found := objs.Find(ObjectSid, AttributeValueSID(usersid)); found {
			computerobject.Pwns(user, PwnLocalSessionLastMonth, 10)
		}
	}

	// AUTOLOGIN CREDENTIALS
	if cinfo.Machine.DefaultUsername != "" && cinfo.Machine.DefaultDomain != "" {
		if cinfo.Machine.DefaultDomain == objs.DomainNetbios {
			// NETBIOS name for domain check FIXME
			account, found := objs.Find(SAMAccountName, AttributeValueString(cinfo.Machine.DefaultUsername))
			if found {
				computerobject.Pwns(account, PwnHasAutoAdminLogonCredentials, 100)
			}
		}
	}

	// SERVICES
	for _, service := range cinfo.Services {
		serviceobject := NewObject(
			DistinguishedName, AttributeValueString("CN="+service.Name+",CN=Services,"+computerobject.DN()),
			DisplayName, AttributeValueString(service.Name),
			ObjectCategory, AttributeValueString("Service"),
		)
		AllObjects.Add(serviceobject)

		computerobject.Pwns(serviceobject, PwnHosts, 100)

		nameparts := strings.Split(service.Account, "\\")
		if len(nameparts) == 2 && nameparts[0] == objs.DomainNetbios {
			svcaccount, found := objs.Find(SAMAccountName, AttributeValueString(nameparts[1]))
			if found {
				computerobject.Pwns(svcaccount, PwnHasServiceAccountCredentials, 100)

				serviceobject.Pwns(svcaccount, PwnRunsAs, 100)
			}
		}

		if ownersid, err := SIDFromString(service.ImageExecutableOwner); err == nil {
			if owner, found := AllObjects.Find(ObjectSid, AttributeValueSID(ownersid)); found {
				owner.Pwns(serviceobject, PwnOwns, 100)
			}
		}

		// Change service executable via registry
		if sd, err := parseACL(service.RegistryDACL); err == nil {
			for _, entry := range sd.Entries {
				if entry.Flags&ACETYPE_ACCESS_ALLOWED != 0 && entry.SID.Component(2) == 21 {
					// AD object
					if o, found := AllObjects.Find(ObjectSid, AttributeValueSID(entry.SID)); found {
						if entry.Mask&KEY_SET_VALUE != KEY_SET_VALUE {
							o.Pwns(serviceobject, PwnWriteAll, 100)
						}
						if entry.Mask&RIGHT_WRITE_DACL != RIGHT_WRITE_DACL {
							o.Pwns(serviceobject, PwnWriteDACL, 100)
						}
					}
				}
			}
			// log.Debug().Msgf("%v registr %v", service.Name, sd)
		}

		// Change service executable contents
		if sd, err := parseACL(service.ImageExecutableDACL); err == nil {
			serviceimageobject := NewObject(
				DistinguishedName, AttributeValueString("cn="+service.ImageExecutable+","+serviceobject.DN()),
				DisplayName, AttributeValueString(service.ImageExecutable),
				ObjectClass, AttributeValueString("Executable"),
			)
			AllObjects.Add(serviceimageobject)

			serviceimageobject.Pwns(serviceobject, PwnExecuted, 100)

			for _, entry := range sd.Entries {
				if entry.Flags&ACETYPE_ACCESS_ALLOWED != 0 && entry.SID.Component(2) == 21 {
					// AD object
					if o, found := AllObjects.Find(ObjectSid, AttributeValueSID(entry.SID)); found {
						if entry.Mask&FILE_WRITE_DATA != FILE_WRITE_DATA {
							o.Pwns(serviceimageobject, PwnWriteAll, 100)
						}
						if entry.Mask&RIGHT_WRITE_OWNER != RIGHT_WRITE_OWNER {
							o.Pwns(serviceimageobject, PwnTakeOwnership, 100) // Not sure about this one
						}
						if entry.Mask&RIGHT_WRITE_DACL != RIGHT_WRITE_DACL {
							o.Pwns(serviceimageobject, PwnWriteDACL, 100)
						}
					}
				}
			}
			// log.Debug().Msgf("Service %v executable %v: %v", service.Name, service.ImageExecutable, sd)
		}
	}

	// MACHINE AVAILABILITY

	// SOFTWARE INVENTORY AS ATTRIBUTES
	installedsoftware := make(AttributeValueSlice, len(cinfo.Software))
	for i, software := range cinfo.Software {
		installedsoftware[i] = AttributeValueString(fmt.Sprintf(
			"%v %v %v", software.Publisher, software.DisplayName, software.DisplayVersion,
		))
	}
	if len(installedsoftware) > 0 {
		computerobject.Attributes[A("_InstalledSoftware")] = installedsoftware
	}
	return nil
}
