package localmachine

//go:generate easyjson -all structs.go

import (
	"net"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/go-win64api/shared"
	"github.com/rickb777/date/period"
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
	State          string    // the operational state of the registered task
	MissedRuns     uint      // the number of times the registered task has missed a scheduled run
	NextRunTime    time.Time // the time when the registered task is next scheduled to run
	LastRunTime    time.Time // the time the registered task was last run
	LastTaskResult uint32    // the results that were returned the last time the registered task was run
}

type TaskDefinition struct {
	Actions          []string
	Context          string // specifies the security context under which the actions of the task are performed
	Data             string // the data that is associated with the task
	Principal        Principal
	RegistrationInfo RegistrationInfo
	Settings         TaskSettings
	Triggers         []string
	XMLText          string // the XML-formatted definition of the task
}

type Principal struct {
	Name      string // the name of the principal
	GroupID   string // the identifier of the user group that is required to run the tasks
	ID        string // the identifier of the principal
	LogonType int    // the security logon method that is required to run the tasks
	RunLevel  int    // the identifier that is used to specify the privilege level that is required to run the tasks
	UserID    string // the user identifier that is required to run the tasks
}

type RegistrationInfo struct {
	Author             string
	Date               time.Time
	Description        string
	Documentation      string
	SecurityDescriptor string
	Source             string
	URI                string
	Version            string
}

type TaskSettings struct {
	AllowDemandStart   bool // indicates that the task can be started by using either the Run command or the Context menu
	AllowHardTerminate bool // indicates that the task may be terminated by the Task Scheduler service using TerminateProcess
	// Compatibility          TaskCompatibility // indicates which version of Task Scheduler a task is compatible with
	DeleteExpiredTaskAfter string        // the amount of time that the Task Scheduler will wait before deleting the task after it expires
	DontStartOnBatteries   bool          // indicates that the task will not be started if the computer is running on batteries
	Enabled                bool          // indicates that the task is enabled
	TimeLimit              period.Period // the amount of time that is allowed to complete the task
	Hidden                 bool          // indicates that the task will not be visible in the UI
	// IdleSettings
	// MultipleInstances TaskInstancesPolicy // defines how the Task Scheduler deals with multiple instances of the task
	// NetworkSettings
	Priority                  uint          // the priority level of the task, ranging from 0 - 10, where 0 is the highest priority, and 10 is the lowest. Only applies to ComHandler, Email, and MessageBox actions
	RestartCount              uint          // the number of times that the Task Scheduler will attempt to restart the task
	RestartInterval           period.Period // specifies how long the Task Scheduler will attempt to restart the task
	RunOnlyIfIdle             bool          // indicates that the Task Scheduler will run the task only if the computer is in an idle condition
	RunOnlyIfNetworkAvailable bool          // indicates that the Task Scheduler will run the task only when a network is available
	StartWhenAvailable        bool          // indicates that the Task Scheduler can start the task at any time after its scheduled time has passed
	StopIfGoingOnBatteries    bool          // indicates that the task will be stopped if the computer is going onto batteries
	WakeToRun                 bool          // indicates that the Task Scheduler will wake the computer when it is time to run the task, and keep the computer awake until the task is completed
}
