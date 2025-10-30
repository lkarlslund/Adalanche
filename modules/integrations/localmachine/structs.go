package localmachine

//go:generate go tool github.com/tinylib/msgp -file structs.go
import (
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

type Info struct {
	basedata.Common
	RegistryData RegistryData `json:",omitempty"`
	Machine      Machine
	LoginInfos   []LogonInfo `json:",omitempty"`
	// Hardware        shared.Hardware        `json:",omitempty"`
	Network                                 NetworkInformation
	Users                                   Users            `json:",omitempty"`
	Groups                                  Groups           `json:",omitempty"`
	Shares                                  Shares           `json:",omitempty"`
	Services                                Services         `json:",omitempty"`
	ServiceControlManagerSecurityDescriptor []byte           `json:",omitempty"`
	Software                                []Software       `json:",omitempty"`
	Tasks                                   []RegisteredTask `json:",omitempty"`
	Privileges                              Privileges       `json:",omitempty"`
	// OperatingSystem shared.OperatingSystem `json:",omitempty"`
	// Memory          shared.Memory          `json:",omitempty"`
	Availability           Availability
	UnprivilegedCollection bool `json:",omitempty"` // True if we know that the collector ran without admin rights, so some data will be missing
}
type Machine struct {
	Name              string `json:",omitempty"`
	LocalSID          string `json:",omitempty"`
	Domain            string `json:",omitempty"`
	ComputerDomainSID string `json:",omitempty"`
	Architecture      string `json:",omitempty"`
	ProductName       string `json:",omitempty"`
	ProductType       string `json:",omitempty"`
	ProductSuite      string `json:",omitempty"`
	EditionID         string `json:",omitempty"`
	ReleaseID         string `json:",omitempty"`
	BuildBranch       string `json:",omitempty"`
	Version           string `json:",omitempty"`
	BuildNumber       string `json:",omitempty"`
	DisplayVersion    string `json:",omitempty"`
	BuildLab          string `json:",omitempty"`
	LCUVer            string `json:",omitempty"`

	DefaultUsername    string   `json:",omitempty"`
	DefaultDomain      string   `json:",omitempty"`
	AltDefaultUsername string   `json:",omitempty"`
	AltDefaultDomain   string   `json:",omitempty"`
	SCCMLastValidMP    string   `json:",omitempty"`
	WUServer           string   `json:",omitempty"`
	WUStatusServer     string   `json:",omitempty"`
	AppCache           [][]byte `json:",omitempty"`
	NumberOfProcessors int      `json:",omitempty"`
	MajorVersionNumber uint64   `json:",omitempty"`
	IsDomainJoined     bool     `json:",omitempty"`
}
type Availability struct {
	Day   uint64 `json:",omitempty"`
	Week  uint64 `json:",omitempty"`
	Month uint64 `json:",omitempty"`
}

type LogonInfo struct {
	User                      string   `json:",omitempty"`
	Domain                    string   `json:",omitempty"`
	SID                       string   `json:",omitempty"`
	Count                     uint64   `json:",omitempty"`
	LogonType                 uint32   `json:",omitempty"`
	AuthenticationPackageName string   `json:",omitempty"`
	IpAddress                 []string `json:",omitempty"`
	FirstSeen                 time.Time
	LastSeen                  time.Time
}
type Shares []Share
type Share struct {
	Name        string `json:",omitempty"`
	Path        string `json:",omitempty"`
	Remark      string `json:",omitempty"`
	PathOwner   string `json:",omitempty"`
	DACL        []byte `json:",omitempty"`
	PathDACL    []byte `json:",omitempty"`
	Permissions int    `json:",omitempty"`
	Type        int    `json:",omitempty"`
}
type RegistryData map[string]any
type Services []Service
type Service struct {
	RegistryOwner        string   `json:",omitempty"`
	Name                 string   `json:",omitempty"`
	DisplayName          string   `json:",omitempty"`
	Description          string   `json:",omitempty"`
	ImagePath            string   `json:",omitempty"`
	ImageExecutable      string   `json:",omitempty"`
	ImageExecutableOwner string   `json:",omitempty"`
	Account              string   `json:",omitempty"`
	AccountSID           string   `json:",omitempty"`
	RegistryDACL         []byte   `json:",omitempty"`
	ImageExecutableDACL  []byte   `json:",omitempty"`
	RequiredPrivileges   []string `json:",omitempty"`
	Start                int      `json:",omitempty"`
	Type                 int      `json:",omitempty"`
	SecurityDescriptor   []byte   `json:",omitempty"`
}
type Software struct {
	InstallDate     time.Time `json:"installDate"`
	DisplayName     string    `json:"displayName"`
	DisplayVersion  string    `json:"displayVersion"`
	Arch            string    `json:"arch"`
	Publisher       string    `json:"publisher"`
	Contact         string    `json:"Contact"`
	HelpLink        string    `json:"HelpLink"`
	InstallSource   string    `json:"InstallSource"`
	InstallLocation string    `json:"InstallLocation"`
	UninstallString string    `json:"UninstallString"`
	EstimatedSize   uint64    `json:"estimatedSize"`
	VersionMajor    uint64    `json:"VersionMajor"`
	VersionMinor    uint64    `json:"VersionMinor"`
}
type Users []User
type User struct {
	PasswordLastSet      time.Time
	LastLogon            time.Time
	LastLogoff           time.Time
	Name                 string `json:",omitempty"`
	SID                  string `json:",omitempty"`
	FullName             string `json:",omitempty"`
	BadPasswordCount     int    `json:",omitempty"`
	NumberOfLogins       int    `json:",omitempty"`
	IsEnabled            bool   `json:",omitempty"`
	IsLocked             bool   `json:",omitempty"`
	IsAdmin              bool   `json:",omitempty"`
	PasswordNeverExpires bool   `json:",omitempty"`
	NoChangePassword     bool   `json:",omitempty"`
}
type Groups []Group
type Group struct {
	Name    string   `json:",omitempty"`
	SID     string   `json:",omitempty"`
	Comment string   `json:",omitempty"`
	Members []Member `json:",omitempty"`
}
type Member struct {
	Name string `json:",omitempty"`
	SID  string `json:",omitempty"`
}
type Privileges []Privilege
type Privilege struct {
	Name         string   `json:",omitempty"`
	AssignedSIDs []string `json:",omitempty"`
}
type NetworkInformation struct {
	InternetConnectivity string                 `json:",omitempty"`
	NetworkInterfaces    []NetworkInterfaceInfo `json:",omitempty"`
}
type NetworkInterfaceInfo struct {
	// Hardware   net.Interface
	Name       string   `json:",omitempty"`
	MACAddress string   `json:",omitempty"`
	Addresses  []string `json:",omitempty"`
	Flags      uint     `json:",omitempty"`
}
type RegisteredTask struct {
	NextRunTime    time.Time
	LastRunTime    time.Time
	Definition     TaskDefinition
	Name           string `json:",omitempty"`
	Path           string `json:",omitempty"`
	State          string `json:",omitempty"`
	MissedRuns     uint   `json:",omitempty"`
	LastTaskResult uint32 `json:",omitempty"`
	Enabled        bool   `json:",omitempty"`
}
type TaskDefinition struct {
	RegistrationInfo RegistrationInfo
	Principal        Principal
	Context          string `json:",omitempty"`
	Data             string `json:",omitempty"`
	XMLText          string `json:",omitempty"`
	Settings         TaskSettings
	Actions          []TaskAction `json:",omitempty"`
	Triggers         []string     `json:",omitempty"`
}
type TaskAction struct {
	Type       string `json:",omitempty"`
	PathOwner  string `json:",omitempty"`
	Path       string `json:",omitempty"`
	Args       string `json:",omitempty"`
	WorkingDir string `json:",omitempty"`
	PathDACL   []byte `json:",omitempty"`
}
type Principal struct {
	Name      string `json:",omitempty"`
	GroupID   string `json:",omitempty"`
	ID        string `json:",omitempty"`
	UserID    string `json:",omitempty"`
	LogonType int    `json:",omitempty"`
	RunLevel  int    `json:",omitempty"`
}
type RegistrationInfo struct {
	Author             string `json:",omitempty"`
	Date               time.Time
	Description        string `json:",omitempty"`
	Documentation      string `json:",omitempty"`
	SecurityDescriptor string `json:",omitempty"`
	Source             string `json:",omitempty"`
	URI                string `json:",omitempty"`
	Version            string `json:",omitempty"`
}
type TaskSettings struct {
	DeleteExpiredTaskAfter    string `json:",omitempty"`
	TimeLimit                 string `json:",omitempty"`
	RestartInterval           string `json:",omitempty"`
	Priority                  uint   `json:",omitempty"`
	RestartCount              uint   `json:",omitempty"`
	AllowDemandStart          bool   `json:",omitempty"`
	AllowHardTerminate        bool   `json:",omitempty"`
	DontStartOnBatteries      bool   `json:",omitempty"`
	Enabled                   bool   `json:",omitempty"`
	Hidden                    bool   `json:",omitempty"`
	RunOnlyIfIdle             bool   `json:",omitempty"`
	RunOnlyIfNetworkAvailable bool   `json:",omitempty"`
	StartWhenAvailable        bool   `json:",omitempty"`
	StopIfGoingOnBatteries    bool   `json:",omitempty"`
	WakeToRun                 bool   `json:",omitempty"`
}
