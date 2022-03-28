package localmachine

//go:generate easyjson -all structs.go

import (
	"net"
	"time"

	"github.com/amidaware/taskmaster"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/go-win64api/shared"
)

type Info struct {
	basedata.Common

	Machine         Machine `json:",omitempty"`
	Hardware        shared.Hardware
	Network         NetworkInformation
	OperatingSystem shared.OperatingSystem
	Memory          shared.Memory

	Availability    Availability
	LoginPopularity LoginPopularity

	Users      Users             `json:",omitempty"`
	Groups     Groups            `json:",omitempty"`
	Shares     Shares            `json:",omitempty"`
	Services   Services          `json:",omitempty"`
	Software   []shared.Software `json:",omitempty"`
	Tasks      []RegisteredTask  `json:",omitempty"`
	Privileges Privileges        `json:",omitempty"`
}

type Machine struct {
	Name              string `json:",omitempty"`
	LocalSID          string `json:",omitempty"`
	Domain            string `json:",omitempty"`
	ComputerDomainSID string `json:",omitempty"`
	IsDomainJoined    bool   `json:",omitempty"`

	Architecture       string `json:",omitempty"`
	NumberOfProcessors int    `json:",omitempty"`

	ProductName        string `json:",omitempty"`
	ProductType        string `json:",omitempty"`
	ProductSuite       string `json:",omitempty"`
	EditionID          string `json:",omitempty"`
	ReleaseID          string `json:",omitempty"`
	BuildBranch        string `json:",omitempty"`
	MajorVersionNumber uint64 `json:",omitempty"`
	Version            string `json:",omitempty"`
	BuildNumber        string `json:",omitempty"`

	DefaultUsername    string `json:",omitempty"`
	DefaultDomain      string `json:",omitempty"`
	AltDefaultUsername string `json:",omitempty"`
	AltDefaultDomain   string `json:",omitempty"`

	AppCache [][]byte `json:",omitempty"`

	SCCMLastValidMP string `json:",omitempty"`

	UACConsentPromptBehaviorAdmin    uint64 `json:",omitempty"`
	UACEnableLUA                     uint64 `json:",omitempty"`
	UACLocalAccountTokenFilterPolicy uint64 `json:",omitempty"`
	UACFilterAdministratorToken      uint64 `json:",omitempty"`
}

type Availability struct {
	Day   uint64 `json:",omitempty"`
	Week  uint64 `json:",omitempty"`
	Month uint64 `json:",omitempty"`
}

type LoginPopularity struct {
	Day   []LoginCount
	Week  []LoginCount
	Month []LoginCount
}

type LoginCount struct {
	Name  string
	SID   string
	Count uint64
}

type Shares []Share
type Share struct {
	Name        string `json:",omitempty"`
	Path        string `json:",omitempty"`
	Remark      string `json:",omitempty"`
	Permissions int    `json:",omitempty"`
	Type        int    `json:",omitempty"`
	DACL        []byte `json:",omitempty"`
	PathDACL    []byte `json:",omitempty"`
	PathOwner   string `json:",omitempty"`
}

type Services []Service
type Service struct {
	RegistryDACL []byte `json:",omitempty"`

	Name        string `json:",omitempty"`
	DisplayName string `json:",omitempty"`
	Description string `json:",omitempty"`

	ImagePath            string `json:",omitempty"`
	ImageExecutable      string `json:",omitempty"`
	ImageExecutableOwner string `json:",omitempty"`
	ImageExecutableDACL  []byte `json:",omitempty"`

	Start int `json:",omitempty"`
	Type  int `json:",omitempty"`

	Account    string `json:",omitempty"`
	AccountSID string `json:",omitempty"`
}

type Users []User
type User struct {
	Name                 string
	SID                  string
	FullName             string
	IsEnabled            bool
	IsLocked             bool
	IsAdmin              bool
	PasswordNeverExpires bool
	NoChangePassword     bool
	PasswordLastSet      time.Time
	LastLogon            time.Time
	LastLogoff           time.Time
	BadPasswordCount     int
	NumberOfLogins       int
}

type Groups []Group
type Group struct {
	Name    string
	SID     string
	Comment string
	Members []Member
}
type Member struct {
	Name string
	SID  string
}

type Privileges []Privilege
type Privilege struct {
	Name         string
	AssignedSIDs []string
}

type NetworkInformation struct {
	InternetConnectivity string
	NetworkInterfaces    []NetworkInterfaceInfo
}
type NetworkInterfaceInfo struct {
	// Hardware   net.Interface
	Name       string
	MACAddress string
	Flags      net.Flags
	Addresses  []string
}

type RegisteredTask struct {
	Name           string // the name of the registered task
	Path           string // the path to where the registered task is stored
	Definition     TaskDefinition
	Enabled        bool
	State          taskmaster.TaskState  // the operational state of the registered task
	MissedRuns     uint                  // the number of times the registered task has missed a scheduled run
	NextRunTime    time.Time             // the time when the registered task is next scheduled to run
	LastRunTime    time.Time             // the time the registered task was last run
	LastTaskResult taskmaster.TaskResult // the results that were returned the last time the registered task was run
}

type TaskDefinition struct {
	Actions          []string
	Context          string // specifies the security context under which the actions of the task are performed
	Data             string // the data that is associated with the task
	Principal        taskmaster.Principal
	RegistrationInfo taskmaster.RegistrationInfo
	Settings         taskmaster.TaskSettings
	Triggers         []string
	XMLText          string // the XML-formatted definition of the task
}

func ConvertRegisteredTask(rt taskmaster.RegisteredTask) RegisteredTask {
	return RegisteredTask{
		Name: rt.Name,
		Path: rt.Path,
		Definition: TaskDefinition{
			Actions: func() []string {
				a := make([]string, len(rt.Definition.Actions))
				for i, v := range rt.Definition.Actions {
					a[i] = v.GetType().String()
				}
				return a
			}(),
			Context:          rt.Definition.Context,
			Data:             rt.Definition.Data,
			Principal:        rt.Definition.Principal,
			RegistrationInfo: rt.Definition.RegistrationInfo,
			Settings:         rt.Definition.Settings,
			Triggers: func() []string {
				a := make([]string, len(rt.Definition.Triggers))
				for i, v := range rt.Definition.Triggers {
					a[i] = v.GetType().String()
				}
				return a
			}(),
			XMLText: rt.Definition.XMLText,
		},
		Enabled:        rt.Enabled,
		State:          rt.State,
		MissedRuns:     rt.MissedRuns,
		NextRunTime:    rt.NextRunTime,
		LastRunTime:    rt.LastRunTime,
		LastTaskResult: rt.LastTaskResult,
	}

}
