package analyze

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"golang.org/x/text/encoding/unicode"
	"gopkg.in/ini.v1"
)

var (
	gPCFileSysPath          = engine.NewAttribute("gPCFileSysPath")
	gpoFlags                = engine.NewAttribute("flags")
	gpoDirectoryVersion     = engine.NewAttribute("versionNumber")
	gpoFunctionalityVersion = engine.NewAttribute("gPCFunctionalityVersion")
	gpoFileVersion          = engine.NewAttribute("gpoFileSystemVersion")

	AbsolutePath         = engine.NewAttribute("absolutePath").Flag(engine.Single)
	RelativePath         = engine.NewAttribute("relativePath").Flag(engine.Single)
	BinarySize           = engine.NewAttribute("binarySize").Flag(engine.Single)
	ExposedPassword      = engine.NewAttribute("exposedPassword")
	GPOCollectionResults = engine.NewAttribute("gpoCollectionResults")

	EdgeExposesPassword       = engine.NewEdge("ExposesPassword").Tag("Pivot")
	EdgeContainsSensitiveData = engine.NewEdge("ContainsSensitiveData")
	EdgeReadSensitiveData     = engine.NewEdge("ReadSensitiveData")
	EdgeOwns                  = engine.NewEdge("Owns")
	EdgeFSPartOfGPO           = engine.NewEdge("FSPartOfGPO")
	EdgeFileCreate            = engine.NewEdge("FileCreate")
	EdgeDirCreate             = engine.NewEdge("DirCreate")
	EdgeFileWrite             = engine.NewEdge("FileWrite")
	EdgeTakeOwnership         = engine.NewEdge("FileTakeOwnership").Tag("Pivot")
	EdgeModifyDACL            = engine.NewEdge("FileModifyDACL").Tag("Pivot")
)

var cpasswordusername = regexp.MustCompile(`(?i)cpassword="(?P<password>[^"]+)[^>]+(runAs|userName)="(?P<username>[^"]+)"`)
var usernamecpassword = regexp.MustCompile(`(?i)(runAs|userName)="(?P<username>[^"]+)[^>]+cpassword="(?P<password>[^"]+)"`)

// ImportGPOInfo adds a policy collection to the graph in one transaction.
// Nothing is added when the import fails.
func ImportGPOInfo(ginfo activedirectory.GPOdump, ao *engine.IndexedGraph) error {
	tx := ao.Begin("policy " + ginfo.Path)
	if err := importGPOInfo(ginfo, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func importGPOInfo(ginfo activedirectory.GPOdump, tx *engine.Tx) error {
	// The GPO is identified by its domain and GUID, which the directory's
	// GPO object and machines' policy results also carry. A path that is not
	// a SYSVOL policy path keeps its own node.
	identity := activedirectory.GPOIdentityFromPath(ginfo.Path)
	domainContext := ginfo.DomainDN
	if domainContext == "" && identity != "" {
		domain, _, _ := strings.Cut(identity, "/")
		domainContext = "DC=" + strings.Join(strings.Split(domain, "."), ",DC=")
	}
	var gpoobject engine.TxNode
	if identity != "" {
		gpoobject, _ = tx.FindOrAdd(activedirectory.GPOIdentity, engine.NV(identity),
			gPCFileSysPath, engine.NV(ginfo.Path))
	} else {
		gpoobject, _ = tx.FindOrAdd(gPCFileSysPath, engine.NV(ginfo.Path))
	}
	// Builtin principals in the GPO's files and ACLs are those of its domain.
	gpoobject.SetFlex(engine.IgnoreBlanks, engine.DomainContext, domainContext)
	if err := retainPolicyResults(gpoobject, ginfo.Common, ginfo.CollectionResults); err != nil {
		return err
	}

	for _, item := range ginfo.Files {
		relativepath := strings.ToLower(strings.ReplaceAll(item.RelativePath, "\\", "/"))
		if relativepath == "" {
			relativepath = "/"
		}

		absolutepath := filepath.Join(ginfo.Path, relativepath)

		objecttype := "File"
		if item.IsDir {
			objecttype = "Directory"
		}

		itemobject := tx.AddNew(
			engine.IgnoreBlanks,
			AbsolutePath, absolutepath,
			RelativePath, relativepath,
			engine.DisplayName, relativepath,
			engine.Type, objecttype,
			BinarySize, item.Size,
			activedirectory.WhenChanged, item.Timestamp,
		)
		if err := retainPolicyResults(itemobject, ginfo.Common, item.CollectionResults); err != nil {
			return err
		}

		if relativepath == "/gpt.ini" || relativepath == "gpt.ini" {
			if status := item.CollectionResults["contents"].Status; status != basedata.CollectionUnknown && status != basedata.CollectionCollected {
				continue
			}
			if policy, err := ini.LoadSources(ini.LoadOptions{Insensitive: true}, item.Contents); err == nil {
				if version, err := policy.Section("General").Key("Version").Uint64(); err == nil && version <= 0xffffffff {
					gpoobject.Set(gpoFileVersion, engine.NV(int64(version)))
				}
			}
			continue
		}
		if strings.EqualFold(relativepath, "/adm") {
			// not really useful from an attack perspective
			continue
		}
		if relativepath == "/" {
			tx.EdgeBecause(itemobject, gpoobject, EdgeFSPartOfGPO, Inferred("the GPO's SYSVOL folder"))
			itemobject.ChildOf(gpoobject)
		} else {
			parentpath := filepath.Join(ginfo.Path, filepath.Dir(relativepath))
			if parentpath == "" {
				parentpath = "/"
			}

			parent, _ := tx.FindOrAdd(AbsolutePath, engine.NV(parentpath))
			tx.EdgeBecause(itemobject, parent, EdgeFSPartOfGPO, Inferred("the GPO's SYSVOL folder"))
			itemobject.ChildOf(parent)
		}

		if !item.OwnerSID.IsNull() {
			owner := tx.FindOrAddAdjacentSID(item.OwnerSID, gpoobject)
			tx.EdgeBecause(owner, itemobject, EdgeOwns, FileOwnerCause())
		}

		if item.DACL != nil {
			dacl, err := engine.ParseACL(item.DACL)
			if err != nil {
				return err
			}
			for index, entry := range dacl.Entries {
				entrysidobject := tx.FindOrAddAdjacentSID(entry.SID, gpoobject)

				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.SID.Component(2) == 21 || entry.SID == windowssecurity.EveryoneSID || entry.SID == windowssecurity.AuthenticatedUsersSID) {
					if item.IsDir && entry.Mask&engine.FILE_ADD_FILE != 0 {
						tx.EdgeBecause(entrysidobject, itemobject, EdgeFileCreate, FileACECause(index, entry))
					}
					if item.IsDir && entry.Mask&engine.FILE_ADD_SUBDIRECTORY != 0 {
						tx.EdgeBecause(entrysidobject, itemobject, EdgeDirCreate, FileACECause(index, entry))
					}
					if !item.IsDir && entry.Mask&engine.FILE_WRITE_DATA != 0 {
						tx.EdgeBecause(entrysidobject, itemobject, EdgeFileWrite, FileACECause(index, entry))
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
						tx.EdgeBecause(entrysidobject, itemobject, EdgeTakeOwnership, FileACECause(index, entry)) // Not sure about this one
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
						tx.EdgeBecause(entrysidobject, itemobject, EdgeModifyDACL, FileACECause(index, entry))
					}
				}
			}
		}

		var exposed []struct{ Username, Password string }

		for line := range strings.SplitSeq(string(item.Contents), "\n") {
			var unhandledpass bool

			// FIXME: Handle other formats, adding something to catch this here
			if strings.Contains(line, "cpassword=") && !strings.Contains(line, "cpassword=\"\"") {
				unhandledpass = true // assume failure
			}
			for _, match := range cpasswordusername.FindAllStringSubmatch(line, -1) {
				ui.Debug().Msgf("Found password in %s", item.RelativePath)
				exposed = append(exposed, struct{ Username, Password string }{match[cpasswordusername.SubexpIndex("username")], match[cpasswordusername.SubexpIndex("password")]})
				unhandledpass = false
			}
			for _, match := range usernamecpassword.FindAllStringSubmatch(line, -1) {
				ui.Debug().Msgf("Found password in %s", item.RelativePath)
				exposed = append(exposed, struct{ Username, Password string }{match[usernamecpassword.SubexpIndex("username")], match[usernamecpassword.SubexpIndex("password")]})
				unhandledpass = false
			}
			if unhandledpass {
				return fmt.Errorf("unrecognized credential entry in GPO file %q; import incomplete", item.RelativePath)
			}
		}
		for _, e := range exposed {
			// New object to contain the sensitive data
			expobj := tx.AddNew(
				engine.Type, "ExposedPassword",
				engine.DisplayName, "Exposed password for "+e.Username,
				engine.Description, "Password is exposed in GPO with GUID "+ginfo.GUID.String(),
				ExposedPassword, e.Password,
				RelativePath, relativepath,
				AbsolutePath, filepath.Join(ginfo.Path, relativepath),
			)

			// The account targeted
			var target engine.TxNode
			if strings.Contains(e.Username, "\\") {
				target, _ = tx.FindOrAdd(
					engine.DownLevelLogonName, engine.NV(e.Username),
				)
			} else {
				target, _ = tx.FindOrAdd(
					engine.SAMAccountName, engine.NV(e.Username),
				)
			}

			// GPO exposes this object
			tx.EdgeBecause(itemobject, expobj, EdgeContainsSensitiveData, engine.Source{Kind: SourceGPO, About: gpoobject, Detail: "Group Policy Preferences password"})
			expobj.ChildOf(itemobject)
			// Exposed password leaks this object
			tx.EdgeBecause(expobj, target, EdgeExposesPassword, engine.Source{Kind: SourceGPO, About: gpoobject, Detail: "Group Policy Preferences password"})

			// Everyone that can read the file can then read the password
			if item.DACL != nil {
				dacl, err := engine.ParseACL(item.DACL)
				if err != nil {
					return err
				}
				for index, entry := range dacl.Entries {
					entrysidobject := tx.FindOrAddAdjacentSID(entry.SID, gpoobject)

					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.SID.Component(2) == 21 || entry.SID == windowssecurity.EveryoneSID || entry.SID == windowssecurity.AuthenticatedUsersSID) {
						if entry.Mask&engine.FILE_READ_DATA != 0 {
							tx.EdgeBecause(entrysidobject, expobj, EdgeReadSensitiveData, FileACECause(index, entry))
						}
					}
				}
			}

		}
		switch relativepath {
		case "/machine/preferences/groups/groups.xml", "/machine/microsoft/windows nt/secedit/gpttmpl.inf":
			var pairs []SIDpair
			setting := gpoGroupPreference
			if strings.HasSuffix(relativepath, ".xml") {
				pairs = GPOparseGroups(string(item.Contents))
			} else if strings.HasSuffix(relativepath, ".inf") {
				pairs = GPOparseGptTmplInf(string(item.Contents))
				setting = gpoRestrictedGroups
			}

			for _, sidpair := range pairs {
				_, known := localGroupEdge(sidpair.GroupSID)
				if !known {
					if sidpair.GroupSID == "" {
						ui.Warn().Msgf("GPO indicating group membership, but no group SID found for %s", sidpair.GroupName)
					}
					continue
				}
				switch {
				case sidpair.MemberSID != "":
					membersid, err := windowssecurity.ParseStringSID(sidpair.MemberSID)
					if err != nil {
						ui.Warn().Msgf("Detected local group membership via GPO, but could not parse SID %v for member %v", sidpair.MemberSID, sidpair.MemberName)
						continue
					}
					// The member gets the right on the machines the GPO
					// applies to, which are known once loading has finished.
					tx.FindOrAddAdjacentSID(membersid, gpoobject)
					gpoobject.Add(GPOLocalGroupMemberSID, engine.NV(gpoGrant{sidpair.GroupSID, membersid.String(), setting}.value()))
				case sidpair.MemberName != "":
					// Names, including ones with preference variables, are
					// resolved after loading, when the whole directory is known.
					gpoobject.Add(GPOLocalGroupMember, engine.NV(gpoGrant{sidpair.GroupSID, sidpair.MemberName, setting}.value()))
				}
			}

		case "/user/preferences/groups/groups.xml":
			// User-side items apply on whichever computer an in-scope user
			// logs on to, which the directory alone does not tell us. Keep
			// them visible on the GPO.
			for _, sidpair := range GPOparseGroups(string(item.Contents)) {
				member := sidpair.MemberName
				switch {
				case sidpair.CurrentUser:
					member = "<logged on user>"
				case sidpair.MemberSID != "":
					member = sidpair.MemberSID
				}
				gpoobject.Add(GPOUserLocalGroupMember, engine.NV(sidpair.GroupSID+"|"+member))
			}

			// Description: "Indicates that a GPO deploys a scheduled task which is running from an UNC path (FIXME, not done yet!)",
		case "/machine/preferences/scheduledtasks/scheduledtasks.xml":
			if tasks := GPOparseScheduledTasks(string(item.Contents)); len(tasks) > 0 {
				ui.Warn().Msgf("GPO scheduled-task analysis is not implemented (%d tasks in %s)", len(tasks), item.RelativePath)
			}
		// Description: "Detects startup or shutdown scripts from GPOs",
		case "/machine/scripts/scripts.ini":
			scripts := string(item.Contents)
			utf8 := make([]byte, len(scripts)/2)
			_, _, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Transform(utf8, []byte(scripts), true)
			if err != nil {
				utf8 = []byte(scripts)
			}

			// ini.LineBreak = "\n"

			inifile, err := ini.LoadSources(ini.LoadOptions{
				SkipUnrecognizableLines: true,
			}, utf8)

			if err != nil {
				ui.Warn().Msgf("Problem loading GPO ini file SCRIPTS.INI from %v: %v", ginfo.Path, err)
			}

			scriptnum := 0
			for {
				k1 := inifile.Section("Startup").Key(fmt.Sprintf("%vCmdLine", scriptnum))
				k2 := inifile.Section("Startup").Key(fmt.Sprintf("%vParameters", scriptnum))
				if k1.String() == "" {
					break
				}
				// Create new synthetic object
				sob := engine.NewNode(
					engine.Type, engine.NV("Script"),
					engine.DistinguishedName, engine.NV(fmt.Sprintf("CN=Startup Script %v from GPO %v,CN=synthetic", scriptnum, ginfo.GUID)),
					engine.Name, engine.NV("Machine startup script "+strings.Trim(k1.String()+" "+k2.String(), " ")),
				)
				script := tx.Add(sob)
				tx.EdgeBecause(script, gpoobject, activedirectory.EdgeMachineScript, engine.Source{Kind: SourceGPO, About: gpoobject, Detail: "machine scripts (scripts.ini)"})
				script.ChildOf(gpoobject) // tree
				scriptnum++
			}

			scriptnum = 0
			for {
				k1 := inifile.Section("Shutdown").Key(fmt.Sprintf("%vCmdLine", scriptnum))
				k2 := inifile.Section("Shutdown").Key(fmt.Sprintf("%vParameters", scriptnum))
				if k1.String() == "" {
					break
				}
				// Create new synthetic object
				sob := engine.NewNode(
					engine.DistinguishedName, engine.NV(fmt.Sprintf("CN=Shutdown Script %v from GPO %v,CN=synthetic", scriptnum, ginfo.GUID)),
					engine.Type, engine.NV("Script"),
					engine.Name, engine.NV("Machine shutdown script "+strings.Trim(k1.String()+" "+k2.String(), " ")),
				)
				script := tx.Add(sob)
				tx.EdgeBecause(script, gpoobject, activedirectory.EdgeMachineScript, engine.Source{Kind: SourceGPO, About: gpoobject, Detail: "machine scripts (scripts.ini)"})
				script.ChildOf(gpoobject)
				scriptnum++
			}
		}
	}

	return nil
}

type ScheduledTasks struct {
	Tasks []TaskV2 `xml:"TaskV2"`
}

type TaskV2 struct {
	UserID   string   `xml:"Properties>Task>Principals>Principal>UserId"`
	RunLevel string   `xml:"Properties>Task>Principals>Principal>RunLevel"`
	Actions  []Action `xml:"Properties>Task>Actions"`
}

type Action struct {
	Command   string `xml:"Exec>Command"`
	Arguments string `xml:"Exec>Arguments"`
}

var (
	uncexec       = regexp.MustCompile(`\\\\.*\\.*\\.*\.(cmd|bat|ps1|vbs|exe|dll)`)
	importantsids = regexp.MustCompile(`^S-1-5-32-(544|555|562)$`)
)

func GPOparseScheduledTasks(rawxml string) []string {
	var results []string
	var tasks ScheduledTasks
	err := xml.Unmarshal([]byte(rawxml), &tasks)
	if err == nil {
		for _, task := range tasks.Tasks {
			if task.RunLevel == "HighestAvailable" {
				for _, action := range task.Actions {
					cmd := action.Command + " " + action.Arguments

					// Check if we're running remote stuff
					if remoteexec := uncexec.FindAllString(cmd, -1); remoteexec != nil {
						results = append(results, remoteexec...)
					}
				}
			}
		}
	}
	return results
}

type Groups struct {
	XMLName xml.Name `xml:"Groups"`
	Group   []Group
}

type Group struct {
	XMLName    xml.Name `xml:"Group"`
	Name       string   `xml:"name,attr"`
	Properties []Properties
}

type Properties struct {
	Action         string `xml:"action,attr"`
	SID            string `xml:"groupSid,attr"`
	Name           string `xml:"groupName,attr"`
	UserAction     string `xml:"userAction,attr"`
	RemoveAccounts string `xml:"removeAccounts,attr"`
	Members        Members
}

type Members struct {
	Member []Member
}

type Member struct {
	// XMLName xml.Name `xml:"Member"`
	Action string `xml:"action,attr"`
	Name   string `xml:"name,attr"`
	SID    string `xml:"sid,attr"`
}

type SIDpair struct {
	GroupSID   string
	GroupName  string
	MemberSID  string
	MemberName string
	// CurrentUser is set when a user-side preference item adds whoever is
	// logged on (userAction="ADD").
	CurrentUser bool
}

// GPOparseGroups returns the local group memberships a Groups.xml preference
// file adds (MS-GPPREF 2.2.1.11). Update (also the default when no action is
// given) and Replace add members; Create leaves an existing group untouched
// and Delete removes it, so neither adds to the built-in groups tracked here.
// A group named only by groupName is translated from its well-known name.
func GPOparseGroups(rawxml string) []SIDpair {
	var results []SIDpair
	var groups Groups
	if err := xml.Unmarshal([]byte(rawxml), &groups); err != nil {
		return nil
	}
	for _, group := range groups.Group {
		for _, prop := range group.Properties {
			action := strings.ToUpper(prop.Action)
			if action != "" && action != "U" && action != "R" {
				continue
			}
			groupsid := prop.SID
			if groupsid == "" {
				if sid, err := TranslateLocalizedNameToSID(strings.TrimSuffix(strings.TrimSpace(prop.Name), " (built-in)")); err == nil {
					groupsid = sid.String()
				}
			}
			if !importantsids.MatchString(groupsid) {
				continue
			}
			for _, member := range prop.Members.Member {
				if strings.EqualFold(member.Action, "ADD") {
					results = append(results, SIDpair{
						GroupSID:   groupsid,
						GroupName:  prop.Name,
						MemberSID:  member.SID,
						MemberName: member.Name,
					})
				}
			}
			if strings.EqualFold(prop.UserAction, "ADD") && prop.RemoveAccounts != "1" {
				results = append(results, SIDpair{GroupSID: groupsid, GroupName: prop.Name, CurrentUser: true})
			}
		}
	}
	return results
}

func GPOparseGptTmplInf(rawini string) []SIDpair {
	var results []SIDpair

	utf8 := make([]byte, len(rawini)/2)
	_, _, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Transform(utf8, []byte(rawini), true)
	if err != nil {
		utf8 = []byte(rawini)
	}

	// ini.LineBreak = "\n"

	gpt, err := ini.LoadSources(ini.LoadOptions{
		SkipUnrecognizableLines: true,
	}, utf8)
	if err == nil {
		for _, key := range gpt.Section("Group Membership").Keys() {
			k := key.Name()
			v := key.String()
			if v == "" {
				// No useful data
				continue
			}
			if strings.HasSuffix(k, "__Memberof") {
				// LHS SID is member of RHS SID groups
				membersid := strings.TrimSuffix(k, "__Memberof")
				var membername string
				if strings.HasPrefix(membersid, "*") {
					// SIDs have an asterisk in front
					membersid = membersid[1:]
				} else {
					// Usernames does not
					membername = membersid
					membersid = ""
					translatedsid, err := TranslateLocalizedNameToSID(membername)
					if err != nil {
						ui.Info().Msgf("GPO GptTmplInf Memberof non-SID member %v translation gave no results, assuming it's a custom name: %v", membername, err)
					} else {
						membersid = translatedsid.String()
					}
				}
				groups := strings.SplitSeq(v, ",")
				for groupsid := range groups {
					var groupname string
					if strings.HasPrefix(groupsid, "*") {
						groupsid = strings.Trim(groupsid[1:], " ")
					} else {
						// Not a SID - using localized group name (thanks, Microsoft)
						// We have a couple we can try - please contribute with more
						groupname = groupsid
						groupsid = ""
						translatedsid, err := TranslateLocalizedNameToSID(groupname)
						if err != nil {
							ui.Info().Msgf("GPO GptTmplInf Memberof non-SID group %v translation gave no results (PLEASE CONTRIBUTE): %v", groupname, err)
						} else {
							groupsid = translatedsid.String()
						}
					}

					results = append(results, SIDpair{
						GroupSID:   groupsid,
						GroupName:  groupname,
						MemberSID:  strings.Trim(membersid, " "),
						MemberName: strings.Trim(membername, " "),
					})
				}
			} else if strings.HasSuffix(k, "__Members") {
				// LHS SID group has RHS SID as members
				groupsid := strings.TrimSuffix(k, "__Members")
				var groupname string
				if strings.HasPrefix(groupsid, "*") {
					groupsid = strings.Trim(groupsid[1:], " ")
				} else {
					// Not a SID - using localized group name (thanks, Microsoft)
					// We have a couple we can try - please contribute with more
					groupname = groupsid
					groupsid = ""
					translatedsid, err := TranslateLocalizedNameToSID(groupname)
					if err != nil {
						// Maybe it's "administrator"?

						ui.Warn().Msgf("GPO GptTmplInf Memberof non-SID group %v translation failed (PLEASE CONTRIBUTE): %v", groupname, err)
					} else {
						groupsid = translatedsid.String()
					}
				}

				members := strings.SplitSeq(v, ",")
				for membersid := range members {
					var membername string
					if strings.HasPrefix(membersid, "*") {
						membersid = membersid[1:]
					} else {
						membername = membersid
						membersid = ""
						translatedsid, err := TranslateLocalizedNameToSID(membername)
						if err != nil {
							ui.Warn().Msgf("GPO GptTmplInf Memberof non-SID member %v translation failed (PLEASE CONTRIBUTE): %v", membername, err)
						} else {
							membersid = translatedsid.String()
						}
					}
					results = append(results, SIDpair{
						GroupSID:   groupsid,
						GroupName:  groupname,
						MemberSID:  membersid,
						MemberName: membername,
					})
				}
			}
		}
	}
	return results
}
