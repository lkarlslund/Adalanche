package main

import (
	"encoding/xml"
	"os"
	"regexp"
)

type ScheduledTasks struct {
	Tasks []TaskV2 `xml:TaskV2`
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
	uncexec       = regexp.MustCompile(`\\\\.*\\.*\.(cmd|bat|ps1|vbs|exe|dll)`)
	importantsids = regexp.MustCompile(`S-1-5-32-(544|555|562)`)
)

func GPOparseScheduledTasksUNCs(path string) []string {
	var results []string
	rawxml, err := os.ReadFile(path + `\Machine\Preferences\ScheduledTasks\ScheduledTasks.XML`)
	if err == nil {
		var tasks ScheduledTasks
		err = xml.Unmarshal(rawxml, &tasks)
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
	}
	return results
}

type Groups struct {
	Groups []Group `xml:Group`
}

type Group struct {
	Action  string   `xml:"Properties>action"`
	SID     string   `xml:"Properties>groupSid"`
	Members []Member `xml:"Properties>Members`
}

type Member struct {
	Name   string `xml:"name"`
	Action string `xml:"action"`
	SID    string `xml:"sid"`
}

type SIDpair struct {
	Group  string
	Member string
}

// SID added to
func GPOparseGroups(path string) []SIDpair {
	var results []SIDpair
	rawxml, err := os.ReadFile(path + `\Machine\Preferences\Groups\Groups.XML`)
	if err == nil {
		var groups Groups
		err = xml.Unmarshal(rawxml, &groups)
		if err == nil {
			for _, group := range groups.Groups {
				if group.Action == "U" && importantsids.MatchString(group.SID) {
					for _, member := range group.Members {
						results = append(results, SIDpair{
							Group:  group.SID,
							Member: member.SID,
						})
					}
				}
			}
		}
	}
	return results
}
