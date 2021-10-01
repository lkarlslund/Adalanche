package collector

//go:generate easyjson -all structs.go

import (
	"time"

	"github.com/lkarlslund/go-win64api/shared"
)

type Info struct {
	Collector string
	BuildDate string
	Commit    string
	Collected time.Time

	Machine         Machine `json:",omitempty"`
	Hardware        shared.Hardware
	OperatingSystem shared.OperatingSystem
	Memory          shared.Memory

	InternetConnectivity string
	Availability         Availability
	LoginPopularity      LoginPopularity

	Users    Users             `json:",omitempty"`
	Groups   Groups            `json:",omitempty"`
	Shares   Shares            `json:",omitempty"`
	Services Services          `json:",omitempty"`
	Software []shared.Software `json:",omitempty"`
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
