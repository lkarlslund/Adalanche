package analyze

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-ini/ini"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"golang.org/x/text/encoding/unicode"
)

var (
	gPCFileSysPath = engine.NewAttribute("gPCFileSysPath").Flag(engine.Merge)

	AbsolutePath    = engine.NewAttribute("absolutePath").Flag(engine.Single)
	RelativePath    = engine.NewAttribute("relativePath").Flag(engine.Single)
	BinarySize      = engine.NewAttribute("binarySize").Flag(engine.Single)
	ExposedPassword = engine.NewAttribute("exposedPassword")

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

func init() {
	engine.AddMergeApprover("Don't merge differing relative paths from GPOs", func(a, b *engine.Node) (*engine.Node, error) {
		if a.HasAttr(RelativePath) || b.HasAttr(RelativePath) {
			return nil, engine.ErrDontMerge
		}
		return nil, nil
	})
}

var cpasswordusername = regexp.MustCompile(`(?i)cpassword="(?P<password>[^"]+)[^>]+(runAs|userName)="(?P<username>[^"]+)"`)
var usernamecpassword = regexp.MustCompile(`(?i)(runAs|userName)="(?P<username>[^"]+)[^>]+cpassword="(?P<password>[^"]+)"`)

func ImportGPOInfo(ginfo activedirectory.GPOdump, ao *engine.IndexedGraph) error {
	gpoobject, _ := ao.FindOrAdd(gPCFileSysPath, engine.NV(ginfo.Path))

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

		itemobject := ao.AddNew(
			engine.IgnoreBlanks,
			AbsolutePath, absolutepath,
			RelativePath, relativepath,
			engine.DisplayName, relativepath,
			engine.Type, objecttype,
			BinarySize, item.Size,
			activedirectory.WhenChanged, item.Timestamp,
		)

		if strings.EqualFold(relativepath, "/adm") ||
			strings.EqualFold(relativepath, "/gpt.ini") {
			// not really useful from an attack perspective
			continue
		}
		if relativepath == "/" {
			ao.EdgeTo(itemobject, gpoobject, EdgeFSPartOfGPO)
			gpoobject.Adopt(itemobject)
		} else {
			parentpath := filepath.Join(ginfo.Path, filepath.Dir(relativepath))
			if parentpath == "" {
				parentpath = "/"
			}

			parent, _ := ao.FindOrAdd(AbsolutePath, engine.NV(parentpath))
			ao.EdgeTo(itemobject, parent, EdgeFSPartOfGPO)
			parent.Adopt(itemobject)
		}

		if !item.OwnerSID.IsNull() {
			owner := ao.FindOrAddAdjacentSID(item.OwnerSID, nil)
			ao.EdgeTo(owner, itemobject, EdgeOwns)
		}

		if item.DACL != nil {
			dacl, err := engine.ParseACL(item.DACL)
			if err != nil {
				return err
			}
			for _, entry := range dacl.Entries {
				entrysidobject, _ := ao.FindOrAdd(activedirectory.ObjectSid, engine.NV(entry.SID))

				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.SID.Component(2) == 21 || entry.SID == windowssecurity.EveryoneSID || entry.SID == windowssecurity.AuthenticatedUsersSID) {
					if item.IsDir && entry.Mask&engine.FILE_ADD_FILE != 0 {
						ao.EdgeTo(entrysidobject, itemobject, EdgeFileCreate)
					}
					if item.IsDir && entry.Mask&engine.FILE_ADD_SUBDIRECTORY != 0 {
						ao.EdgeTo(entrysidobject, itemobject, EdgeDirCreate)
					}
					if !item.IsDir && entry.Mask&engine.FILE_WRITE_DATA != 0 {
						ao.EdgeTo(entrysidobject, itemobject, EdgeFileWrite)
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
						ao.EdgeTo(entrysidobject, itemobject, EdgeTakeOwnership) // Not sure about this one
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
						ao.EdgeTo(entrysidobject, itemobject, EdgeModifyDACL)
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
				ui.Debug().Msgf("Password: %v", match)
				ui.Debug().Msgf("GPO Dump\n%s", item.Contents)
				exposed = append(exposed, struct{ Username, Password string }{match[cpasswordusername.SubexpIndex("username")], match[cpasswordusername.SubexpIndex("password")]})
				unhandledpass = false
			}
			for _, match := range usernamecpassword.FindAllStringSubmatch(line, -1) {
				ui.Debug().Msgf("Found username in %s", item.RelativePath)
				ui.Debug().Msgf("Password: %v", match)
				ui.Debug().Msgf("GPO Dump\n%s", item.Contents)
				exposed = append(exposed, struct{ Username, Password string }{match[usernamecpassword.SubexpIndex("username")], match[usernamecpassword.SubexpIndex("password")]})
				unhandledpass = false
			}
			if unhandledpass {
				ui.Error().Msgf("Unhandled password in %s", item.RelativePath)
				ui.Error().Msgf("GPO Dump\n%s", item.Contents)
				ui.Fatal().Msg("Please submit bugreport on Github with redacted account name and redacted password")
			}
		}
		for _, e := range exposed {
			// New object to contain the sensitive data
			expobj := ao.AddNew(
				engine.Type, "ExposedPassword",
				engine.DisplayName, "Exposed password for "+e.Username,
				engine.Description, "Password is exposed in GPO with GUID "+ginfo.GUID.String(),
				engine.ObjectGUID, ginfo.GUID,
				ExposedPassword, e.Password,
				RelativePath, relativepath,
				AbsolutePath, filepath.Join(ginfo.Path, relativepath),
			)

			// The account targeted
			var target *engine.Node
			if strings.Contains(e.Username, "\\") {
				target, _ = ao.FindOrAdd(
					engine.DownLevelLogonName, engine.NV(e.Username),
				)
			} else {
				target, _ = ao.FindOrAdd(
					engine.SAMAccountName, engine.NV(e.Username),
				)
			}

			// GPO exposes this object
			ao.EdgeTo(itemobject, expobj, EdgeContainsSensitiveData)
			// Exposed password leaks this object
			ao.EdgeTo(expobj, target, EdgeExposesPassword)

			// Everyone that can read the file can then read the password
			if item.DACL != nil {
				dacl, err := engine.ParseACL(item.DACL)
				if err != nil {
					return err
				}
				for _, entry := range dacl.Entries {
					entrysidobject, _ := ao.FindOrAdd(activedirectory.ObjectSid, engine.NV(entry.SID))

					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.SID.Component(2) == 21 || entry.SID == windowssecurity.EveryoneSID || entry.SID == windowssecurity.AuthenticatedUsersSID) {
						if entry.Mask&engine.FILE_READ_DATA != 0 {
							ao.EdgeTo(entrysidobject, expobj, EdgeReadSensitiveData)
						}
					}
				}
			}

		}
		switch relativepath {
		case "/machine/preferences/groups/groups.xml", "/machine/microsoft/windows nt/secedit/gpttmpl.inf":
			var pairs []SIDpair

			if strings.HasSuffix(relativepath, ".xml") {
				pairs = GPOparseGroups(string(item.Contents))
			} else if strings.HasSuffix(relativepath, ".inf") {
				pairs = GPOparseGptTmplInf(string(item.Contents))
			}

			for _, sidpair := range pairs {
				var member *engine.Node
				if sidpair.MemberSID == "" {
					if strings.Contains(sidpair.MemberName, "\\") || strings.Contains(sidpair.MemberName, "@") {
						ui.Debug().Msgf("GPO member with \\ or @ detected: %v", sidpair.MemberName)
					} else {
						// Just use the name, we assume it's a domain object
						member, _ = ao.FindOrAdd(engine.SAMAccountName, engine.NV(sidpair.MemberName))
					}
				} else {
					// Use the SID
					membersid, err := windowssecurity.ParseStringSID(sidpair.MemberSID)
					if err == nil {
						member = ao.FindOrAddSID(membersid)
					}
				}
				if member != nil {
					switch sidpair.GroupSID {
					case "S-1-5-32-544":
						ao.EdgeTo(member, gpoobject, activedirectory.EdgeLocalAdminRights)
					case "S-1-5-32-562":
						ao.EdgeTo(member, gpoobject, activedirectory.EdgeLocalDCOMRights)
					case "S-1-5-32-555":
						ao.EdgeTo(member, gpoobject, activedirectory.EdgeLocalRDPRights)
					case "":
						ui.Warn().Msgf("GPO indicating group membership, but no group SID found for %s", sidpair.GroupName)
					}
				} else {
					ui.Warn().Msgf("Detected local group membership via GPO, but could not parse SID %v for member %v", sidpair.MemberSID, sidpair.MemberName)
				}
			}

			// Description: "Indicates that a GPO deploys a scheduled task which is running from an UNC path (FIXME, not done yet!)",
		case "/machine/preferences/scheduledtasks/scheduledtasks.xml":
			for _, task := range GPOparseScheduledTasks(string(item.Contents)) {
				ui.Warn().Msgf("Scheduled task: %v ... FIXME!", task)
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
				ao.Add(sob)
				ao.EdgeTo(sob, gpoobject, activedirectory.EdgeMachineScript)
				sob.ChildOf(gpoobject) // tree
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
				ao.Add(sob)
				ao.EdgeTo(sob, gpoobject, activedirectory.EdgeMachineScript)
				sob.ChildOf(gpoobject)
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
	importantsids = regexp.MustCompile(`S-1-5-32-(544|555|562)`)
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
	Action  string `xml:"action,attr"`
	SID     string `xml:"groupSid,attr"`
	Name    string `xml:"groupName,attr"`
	Members Members
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
}

func GPOparseGroups(rawxml string) []SIDpair {
	var results []SIDpair
	var groups Groups
	err := xml.Unmarshal([]byte(rawxml), &groups)
	if err == nil {
		for _, group := range groups.Group {
			for _, prop := range group.Properties {
				if prop.Action == "U" && importantsids.MatchString(prop.SID) {
					for _, member := range prop.Members.Member {
						if member.Action == "ADD" {
							results = append(results, SIDpair{
								GroupSID:   prop.SID,
								GroupName:  prop.Name,
								MemberSID:  member.SID,
								MemberName: member.Name,
							})
						}
					}
				}
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
