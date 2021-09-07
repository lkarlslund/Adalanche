package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/lkarlslund/adalanche/modules/collector"
	"github.com/rs/zerolog/log"
)

func importCollectorFiles(path string, objs *Objects) error {
	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
			// Import it
			raw, err := ioutil.ReadFile(path)
			if err != nil {
				log.Warn().Msgf("Problem reading collector file %v: %v", info.Name(), err)
				return nil
			}
			var cinfo collector.Info
			err = json.Unmarshal(raw, &cinfo)
			if err != nil {
				log.Error().Msgf("Problem unmarshalling %v from JSON: %v", info.Name(), err)
				return nil // The show must go on
			}

			//			if !strings.EqualFold(objs.Domain, cinfo.Machine.Domain) {
			//				return nil // Machine is domain joined, but not to this domain!? Ignore for now
			//			}

			// find computer object by SID
			var computerobject *Object
			if cinfo.Machine.ComputerDomainSID != "" {
				csid, err := SIDFromString(cinfo.Machine.ComputerDomainSID)
				if err == nil {
					computerobject, _ = objs.FindSID(csid)
				}
			}

			// Fallback to looking by machine account name
			if computerobject == nil {
				computerobject, err = objs.FindOne(SAMAccountName, cinfo.Machine.Name+"$")
				if err != nil {
					return nil // We didn't find it
				}
			}

			// Save the Info object on the Object, we can use this for presentation later on
			computerobject.collectorinfo = &cinfo

			// Add local accounts as synthetic objects
			// If it brings value ... ?

			// Iterate over Groups
			for _, group := range cinfo.Groups {
				groupsid, err := SIDFromString(group.SID)
				if err != nil {
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
					if member, found := objs.FindSID(membersid); found {
						switch groupsid {
						case SIDAdministrators:
							member.CanPwn.Set(computerobject, PwnLocalAdminRights)
							computerobject.PwnableBy.Set(member, PwnLocalAdminRights)
						case SIDDCOMUsers:
							member.CanPwn.Set(computerobject, PwnLocalDCOMRights)
							computerobject.PwnableBy.Set(member, PwnLocalDCOMRights)
						case SIDRemoteDesktopUsers:
							member.CanPwn.Set(computerobject, PwnLocalRDPRights)
							computerobject.PwnableBy.Set(member, PwnLocalRDPRights)
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
				if user, found := objs.FindSID(usersid); found {
					computerobject.CanPwn.Set(user, PwnLocalSessionLastDay)
					user.PwnableBy.Set(computerobject, PwnLocalSessionLastDay)
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
				if user, found := objs.FindSID(usersid); found {
					computerobject.CanPwn.Set(user, PwnLocalSessionLastWeek)
					user.PwnableBy.Set(computerobject, PwnLocalSessionLastWeek)
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
				if user, found := objs.FindSID(usersid); found {
					computerobject.CanPwn.Set(user, PwnLocalSessionLastMonth)
					user.PwnableBy.Set(computerobject, PwnLocalSessionLastMonth)
				}
			}

			// AUTOLOGIN CREDENTIALS
			if cinfo.Machine.DefaultUsername != "" && cinfo.Machine.DefaultDomain != "" {
				if cinfo.Machine.DefaultDomain == objs.DomainNetbios {
					// NETBIOS name for domain check FIXME
					account, err := objs.FindOne(SAMAccountName, cinfo.Machine.DefaultUsername)
					if err == nil {
						computerobject.CanPwn.Set(account, PwnHasAutoAdminLogonCredentials)
						account.PwnableBy.Set(computerobject, PwnHasAutoAdminLogonCredentials)
					}
				}
			}

			// SERVICES
			for _, service := range cinfo.Services {
				nameparts := strings.Split(service.Account, "\\")
				if len(nameparts) == 2 && nameparts[0] == objs.DomainNetbios {
					svcaccount, err := objs.FindOne(SAMAccountName, nameparts[1])
					if err == nil {
						computerobject.CanPwn.Set(svcaccount, PwnHasServiceAccountCredentials)
						svcaccount.PwnableBy.Set(computerobject, PwnHasServiceAccountCredentials)
					}
				}
			}

			// MACHINE AVAILABILITY

			// SOFTWARE INVENTORY AS ATTRIBUTES
			var installedsoftware []string
			for _, software := range cinfo.Software {
				installedsoftware = append(installedsoftware, fmt.Sprintf(
					"%v %v %v", software.Publisher, software.DisplayName, software.DisplayVersion,
				))
			}
			if len(installedsoftware) > 0 {
				computerobject.Attributes[A("_InstalledSoftware")] = installedsoftware
			}

		}
		return nil
	})

	return nil // FIXME
}
