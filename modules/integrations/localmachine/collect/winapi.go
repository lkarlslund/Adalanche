package collect

import (
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/pkg/errors"
)

type Privilege string

const (
	////////////////////////////////////////////////////////////////////////
	//                                                                    //
	//               NT Defined Privileges                                //
	//                                                                    //
	////////////////////////////////////////////////////////////////////////

	SE_CREATE_TOKEN_NAME                      Privilege = "SeCreateTokenPrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME                Privilege = "SeAssignPrimaryTokenPrivilege"
	SE_LOCK_MEMORY_NAME                       Privilege = "SeLockMemoryPrivilege"
	SE_INCREASE_QUOTA_NAME                    Privilege = "SeIncreaseQuotaPrivilege"
	SE_UNSOLICITED_INPUT_NAME                 Privilege = "SeUnsolicitedInputPrivilege"
	SE_MACHINE_ACCOUNT_NAME                   Privilege = "SeMachineAccountPrivilege"
	SE_TCB_NAME                               Privilege = "SeTcbPrivilege"
	SE_SECURITY_NAME                          Privilege = "SeSecurityPrivilege"
	SE_TAKE_OWNERSHIP_NAME                    Privilege = "SeTakeOwnershipPrivilege"
	SE_LOAD_DRIVER_NAME                       Privilege = "SeLoadDriverPrivilege"
	SE_SYSTEM_PROFILE_NAME                    Privilege = "SeSystemProfilePrivilege"
	SE_SYSTEMTIME_NAME                        Privilege = "SeSystemtimePrivilege"
	SE_PROF_SINGLE_PROCESS_NAME               Privilege = "SeProfileSingleProcessPrivilege"
	SE_INC_BASE_PRIORITY_NAME                 Privilege = "SeIncreaseBasePriorityPrivilege"
	SE_CREATE_PAGEFILE_NAME                   Privilege = "SeCreatePagefilePrivilege"
	SE_CREATE_PERMANENT_NAME                  Privilege = "SeCreatePermanentPrivilege"
	SE_BACKUP_NAME                            Privilege = "SeBackupPrivilege"
	SE_RESTORE_NAME                           Privilege = "SeRestorePrivilege"
	SE_SHUTDOWN_NAME                          Privilege = "SeShutdownPrivilege"
	SE_DEBUG_NAME                             Privilege = "SeDebugPrivilege"
	SE_AUDIT_NAME                             Privilege = "SeAuditPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME                Privilege = "SeSystemEnvironmentPrivilege"
	SE_CHANGE_NOTIFY_NAME                     Privilege = "SeChangeNotifyPrivilege"
	SE_REMOTE_SHUTDOWN_NAME                   Privilege = "SeRemoteShutdownPrivilege"
	SE_UNDOCK_NAME                            Privilege = "SeUndockPrivilege"
	SE_SYNC_AGENT_NAME                        Privilege = "SeSyncAgentPrivilege"
	SE_ENABLE_DELEGATION_NAME                 Privilege = "SeEnableDelegationPrivilege"
	SE_MANAGE_VOLUME_NAME                     Privilege = "SeManageVolumePrivilege"
	SE_IMPERSONATE_NAME                       Privilege = "SeImpersonatePrivilege"
	SE_CREATE_GLOBAL_NAME                     Privilege = "SeCreateGlobalPrivilege"
	SE_TRUSTED_CREDMAN_ACCESS_NAME            Privilege = "SeTrustedCredManAccessPrivilege"
	SE_RELABEL_NAME                           Privilege = "SeRelabelPrivilege"
	SE_INC_WORKING_SET_NAME                   Privilege = "SeIncreaseWorkingSetPrivilege"
	SE_TIME_ZONE_NAME                         Privilege = "SeTimeZonePrivilege"
	SE_CREATE_SYMBOLIC_LINK_NAME              Privilege = "SeCreateSymbolicLinkPrivilege"
	SE_NETWORK_LOGON_RIGHT                    Privilege = "SeNetworkLogonRight"
	SE_INTERACTIVE_LOGON_NAME                 Privilege = "SeInteractiveLogonRight"
	SE_REMOTE_INTERACTIVE_LOGON_NAME          Privilege = "SeRemoteInteractiveLogonRight"
	SE_DENY_NETWORK_LOGON_NAME                Privilege = "SeDenyNetworkLogonRight"
	SE_DENY_INTERACTIVE_LOGON_NAME            Privilege = "SeDenyInteractiveLogonRight"
	SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME     Privilege = "SeDenyRemoteInteractiveLogonRight"
	SE_DENY_BATCH_LOGON_NAME                  Privilege = "SeDenyBatchLogonRight"
	SE_DENY_SERVICE_LOGON_NAME                Privilege = "SeDenyServiceLogonRight"
	SE_BATCH_LOGON_NAME                       Privilege = "SeBatchLogonRight"
	SE_SERVICE_LOGON_NAME                     Privilege = "SeServiceLogonRight"
	SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME Privilege = "SeDelegateSessionUserImpersonatePrivilege"
)

var (
	PRIVILEGE_NAMES = []Privilege{
		SE_CREATE_TOKEN_NAME,
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_LOCK_MEMORY_NAME,
		SE_INCREASE_QUOTA_NAME,
		SE_UNSOLICITED_INPUT_NAME,
		SE_MACHINE_ACCOUNT_NAME,
		SE_TCB_NAME,
		SE_SECURITY_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_SYSTEM_PROFILE_NAME,
		SE_SYSTEMTIME_NAME,
		SE_PROF_SINGLE_PROCESS_NAME,
		SE_INC_BASE_PRIORITY_NAME,
		SE_CREATE_PAGEFILE_NAME,
		SE_CREATE_PERMANENT_NAME,
		SE_BACKUP_NAME,
		SE_RESTORE_NAME,
		SE_SHUTDOWN_NAME,
		SE_DEBUG_NAME,
		SE_AUDIT_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_CHANGE_NOTIFY_NAME,
		SE_REMOTE_SHUTDOWN_NAME,
		SE_UNDOCK_NAME,
		SE_SYNC_AGENT_NAME,
		SE_ENABLE_DELEGATION_NAME,
		SE_MANAGE_VOLUME_NAME,
		SE_IMPERSONATE_NAME,
		SE_CREATE_GLOBAL_NAME,
		SE_TRUSTED_CREDMAN_ACCESS_NAME,
		SE_RELABEL_NAME,
		SE_INC_WORKING_SET_NAME,
		SE_TIME_ZONE_NAME,
		SE_CREATE_SYMBOLIC_LINK_NAME,
		SE_NETWORK_LOGON_RIGHT,
		SE_INTERACTIVE_LOGON_NAME,
		SE_REMOTE_INTERACTIVE_LOGON_NAME,
		SE_DENY_NETWORK_LOGON_NAME,
		SE_DENY_INTERACTIVE_LOGON_NAME,
		SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME,
		SE_DENY_BATCH_LOGON_NAME,
		SE_DENY_SERVICE_LOGON_NAME,
		SE_BATCH_LOGON_NAME,
		SE_SERVICE_LOGON_NAME,
		SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
	}
)

// Types Reference: https://docs.microsoft.com/en-us/windows/desktop/WinProg/windows-data-types
type (
	BOOL          uint32
	BOOLEAN       byte
	BYTE          byte
	DWORD         uint32
	DWORD64       uint64
	HANDLE        uintptr
	HLOCAL        uintptr
	LARGE_INTEGER int64
	LONG          int32
	LPVOID        uintptr
	SIZE_T        uintptr
	UINT          uint32
	ULONG_PTR     uintptr
	ULONGLONG     uint64
	WORD          uint16
)

var (
	advapi                            = syscall.NewLazyDLL("advapi32.dll")
	lsaAddAccountRights               = advapi.NewProc("LsaAddAccountRights")
	lsaAddPrivilegesToAccount         = advapi.NewProc("LsaAddPrivilegesToAccount")
	lsaClearAuditLog                  = advapi.NewProc("LsaClearAuditLog")
	lsaClose                          = advapi.NewProc("LsaClose")
	lsaCreateAccount                  = advapi.NewProc("LsaCreateAccount")
	lsaCreateSecret                   = advapi.NewProc("LsaCreateSecret")
	lsaCreateTrustedDomain            = advapi.NewProc("LsaCreateTrustedDomain")
	lsaCreateTrustedDomainEx          = advapi.NewProc("LsaCreateTrustedDomainEx")
	lsaDelete                         = advapi.NewProc("LsaDelete")
	lsaDeleteTrustedDomain            = advapi.NewProc("LsaDeleteTrustedDomain")
	lsaEnumerateAccountRights         = advapi.NewProc("LsaEnumerateAccountRights")
	lsaEnumerateAccounts              = advapi.NewProc("LsaEnumerateAccounts")
	lsaEnumerateAccountsWithUserRight = advapi.NewProc("LsaEnumerateAccountsWithUserRight")
	lsaEnumeratePrivileges            = advapi.NewProc("LsaEnumeratePrivileges")
	lsaEnumeratePrivilegesOfAccount   = advapi.NewProc("LsaEnumeratePrivilegesOfAccount")
	lsaEnumerateTrustedDomains        = advapi.NewProc("LsaEnumerateTrustedDomains")
	lsaEnumerateTrustedDomainsEx      = advapi.NewProc("LsaEnumerateTrustedDomainsEx")
	lsaFreeMemory                     = advapi.NewProc("LsaFreeMemory")
	lsaGetQuotasForAccount            = advapi.NewProc("LsaGetQuotasForAccount")
	lsaGetRemoteUserName              = advapi.NewProc("LsaGetRemoteUserName")
	lsaGetSystemAccessAccount         = advapi.NewProc("LsaGetSystemAccessAccount")
	lsaGetUserName                    = advapi.NewProc("LsaGetUserName")
	lsaICLookupNames                  = advapi.NewProc("LsaICLookupNames")
	lsaICLookupNamesWithCreds         = advapi.NewProc("LsaICLookupNamesWithCreds")
	lsaICLookupSids                   = advapi.NewProc("LsaICLookupSids")
	lsaICLookupSidsWithCreds          = advapi.NewProc("LsaICLookupSidsWithCreds")
	lsaLookupNames                    = advapi.NewProc("LsaLookupNames")
	lsaLookupNames2                   = advapi.NewProc("LsaLookupNames2")
	lsaLookupPrivilegeDisplayName     = advapi.NewProc("LsaLookupPrivilegeDisplayName")
	lsaLookupPrivilegeName            = advapi.NewProc("LsaLookupPrivilegeName")
	lsaLookupPrivilegeValue           = advapi.NewProc("LsaLookupPrivilegeValue")
	lsaLookupSids                     = advapi.NewProc("LsaLookupSids")
	lsaManageSidNameMapping           = advapi.NewProc("LsaManageSidNameMapping")
	lsaNtStatusToWinError             = advapi.NewProc("LsaNtStatusToWinError")
	lsaOpenAccount                    = advapi.NewProc("LsaOpenAccount")
	lsaOpenPolicy                     = advapi.NewProc("LsaOpenPolicy")
	lsaOpenPolicySce                  = advapi.NewProc("LsaOpenPolicySce")
	lsaOpenSecret                     = advapi.NewProc("LsaOpenSecret")
	lsaOpenTrustedDomain              = advapi.NewProc("LsaOpenTrustedDomain")
	lsaOpenTrustedDomainByName        = advapi.NewProc("LsaOpenTrustedDomainByName")
	lsaQueryDomainInformationPolicy   = advapi.NewProc("LsaQueryDomainInformationPolicy")
	lsaQueryForestTrustInformation    = advapi.NewProc("LsaQueryForestTrustInformation")
	lsaQueryInfoTrustedDomain         = advapi.NewProc("LsaQueryInfoTrustedDomain")
	lsaQueryInformationPolicy         = advapi.NewProc("LsaQueryInformationPolicy")
	lsaQuerySecret                    = advapi.NewProc("LsaQuerySecret")
	lsaQuerySecurityObject            = advapi.NewProc("LsaQuerySecurityObject")
	lsaQueryTrustedDomainInfo         = advapi.NewProc("LsaQueryTrustedDomainInfo")
	lsaQueryTrustedDomainInfoByName   = advapi.NewProc("LsaQueryTrustedDomainInfoByName")
	lsaRemoveAccountRights            = advapi.NewProc("LsaRemoveAccountRights")
	lsaRemovePrivilegesFromAccount    = advapi.NewProc("LsaRemovePrivilegesFromAccount")
	lsaRetrievePrivateData            = advapi.NewProc("LsaRetrievePrivateData")
	lsaSetDomainInformationPolicy     = advapi.NewProc("LsaSetDomainInformationPolicy")
	lsaSetForestTrustInformation      = advapi.NewProc("LsaSetForestTrustInformation")
	lsaSetInformationPolicy           = advapi.NewProc("LsaSetInformationPolicy")
	lsaSetInformationTrustedDomain    = advapi.NewProc("LsaSetInformationTrustedDomain")
	lsaSetQuotasForAccount            = advapi.NewProc("LsaSetQuotasForAccount")
	lsaSetSecret                      = advapi.NewProc("LsaSetSecret")
	lsaSetSecurityObject              = advapi.NewProc("LsaSetSecurityObject")
	lsaSetSystemAccessAccount         = advapi.NewProc("LsaSetSystemAccessAccount")
	lsaSetTrustedDomainInfoByName     = advapi.NewProc("LsaSetTrustedDomainInfoByName")
	lsaSetTrustedDomainInformation    = advapi.NewProc("LsaSetTrustedDomainInformation")
	lsaStorePrivateData               = advapi.NewProc("LsaStorePrivateData")
)

//	typedef struct _LSA_OBJECT_ATTRIBUTES {
//	  ULONG               Length;
//	  HANDLE              RootDirectory;
//	  PLSA_UNICODE_STRING ObjectName;
//	  ULONG               Attributes;
//	  PVOID               SecurityDescriptor;
//	  PVOID               SecurityQualityOfService;
//	} LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;
type _LSA_OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

//	typedef struct _LSA_UNICODE_STRING {
//	  USHORT Length;
//	  USHORT MaximumLength;
//	} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
//
// https://docs.microsoft.com/en-us/windows/desktop/api/lsalookup/ns-lsalookup-_lsa_unicode_string
type _LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        unsafe.Pointer
}

const (
	NULL uintptr = 0

	ANY_SIZE int = 1

	// Error Codes
	NO_ERROR                  uintptr       = 0
	ERROR_SUCCESS             uintptr       = 0
	ERROR_MORE_DATA           uintptr       = 0xea // 234
	ERROR_MR_MID_NOT_FOUND    uintptr       = 317
	STATUS_NO_MORE_ENTRIES    syscall.Errno = 0x8000001A
	NO_MORE_DATA_IS_AVAILABLE syscall.Errno = 0x80070103

	// Booleans
	FALSE BOOL = 0
	TRUE  BOOL = 1

	// Constants
	DWORD_MAX = DWORD(0xFFFFFFFF)

	// Generic Access Rights
	// https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/generic-access-rights

	_GENERIC_READ    uint32 = 0x80000000
	_GENERIC_WRITE   uint32 = 0x40000000
	_GENERIC_EXECUTE uint32 = 0x20000000
	_GENERIC_ALL     uint32 = 0x10000000

	_ACCESS_SYSTEM_SECURITY uint32 = 0x01000000
	_MAXIMUM_ALLOWED        uint32 = 0x02000000

	// Standard Access Rights
	// https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/standard-access-rights

	_DELETE                   uint32 = 0x00010000
	_READ_CONTROL             uint32 = 0x00020000
	_WRITE_DAC                uint32 = 0x00040000
	_WRITE_OWNER              uint32 = 0x00080000
	_SYNCHRONIZE              uint32 = 0x00100000
	_STANDARD_RIGHTS_REQUIRED        = _DELETE | _READ_CONTROL | _WRITE_DAC | _WRITE_OWNER
	_STANDARD_RIGHTS_EXECUTE         = _READ_CONTROL
	_STANDARD_RIGHTS_READ            = _READ_CONTROL
	_STANDARD_RIGHTS_WRITE           = _READ_CONTROL
	_STANDARD_RIGHTS_ALL             = _DELETE | _READ_CONTROL | _WRITE_DAC | _WRITE_OWNER | _SYNCHRONIZE

	// Object-specific Access Rights mask

	_SPECIFIC_RIGHTS_ALL uint32 = 0x0000ffff

	_POLICY_VIEW_LOCAL_INFORMATION   uint32 = 0x0001
	_POLICY_VIEW_AUDIT_INFORMATION   uint32 = 0x0002
	_POLICY_GET_PRIVATE_INFORMATION  uint32 = 0x0004
	_POLICY_TRUST_ADMIN              uint32 = 0x0008
	_POLICY_CREATE_ACCOUNT           uint32 = 0x0010
	_POLICY_CREATE_SECRET            uint32 = 0x0020
	_POLICY_CREATE_PRIVILEGE         uint32 = 0x0040
	_POLICY_SET_DEFAULT_QUOTA_LIMITS uint32 = 0x0080
	_POLICY_SET_AUDIT_REQUIREMENTS   uint32 = 0x0100
	_POLICY_AUDIT_LOG_ADMIN          uint32 = 0x0200
	_POLICY_SERVER_ADMIN             uint32 = 0x0400
	_POLICY_LOOKUP_NAMES             uint32 = 0x0800
	_POLICY_READ                     uint32 = _STANDARD_RIGHTS_READ | 0x0006
	_POLICY_WRITE                    uint32 = _STANDARD_RIGHTS_WRITE | 0x07F8
	_POLICY_EXECUTE                  uint32 = _STANDARD_RIGHTS_EXECUTE | 0x0801
	_POLICY_ALL_ACCESS               uint32 = _STANDARD_RIGHTS_REQUIRED | 0x0FFF
)

func toLSAUnicodeString(str string) _LSA_UNICODE_STRING {
	wchars, _ := syscall.UTF16FromString(str)
	nc := len(wchars) - 1 // minus 1 to chop off the null termination
	sz := int(unsafe.Sizeof(uint16(0)))
	return _LSA_UNICODE_STRING{
		Length:        uint16(nc * sz),
		MaximumLength: uint16((nc + 1) * sz),
		Buffer:        unsafe.Pointer(&wchars[0]),
	}
}

// NTSTATUS values
// https://msdn.microsoft.com/en-us/library/cc704588.aspx
const (
	_STATUS_SUCCESS      uintptr = 0x00000000
	_STATUS_NO_SUCH_FILE uintptr = 0xC000000F
)

// NTSTATUS LsaOpenPolicy(
//
//		PLSA_UNICODE_STRING    SystemName,
//		PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
//		ACCESS_MASK            DesiredAccess,
//		PLSA_HANDLE            PolicyHandle
//	  );
//
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaopenpolicy
func LsaOpenPolicy(system string, access uint32) (*syscall.Handle, error) {
	// Docs say this is not used, but the structure needs to be
	// initialized to zero values, and the length must be set to sizeof(_LSA_OBJECT_ATTRIBUTES)
	var pSystemName *_LSA_UNICODE_STRING
	if system != "" {
		lsaStr := toLSAUnicodeString(system)
		pSystemName = &lsaStr
	}
	var attrs _LSA_OBJECT_ATTRIBUTES
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var hPolicy syscall.Handle
	status, _, _ := lsaOpenPolicy.Call(
		uintptr(unsafe.Pointer(pSystemName)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(access),
		uintptr(unsafe.Pointer(&hPolicy)),
	)
	if status == _STATUS_SUCCESS {
		return &hPolicy, nil
	}
	return nil, LsaNtStatusToWinError(status)
}

// NTSTATUS LsaClose(
//
//	LSA_HANDLE ObjectHandle
//
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaclose
func LsaClose(hPolicy syscall.Handle) error {
	status, _, _ := lsaClose.Call(
		uintptr(hPolicy),
	)
	if status == _STATUS_SUCCESS {
		return nil
	}
	return LsaNtStatusToWinError(status)
}

// NTSTATUS LsaEnumerateAccountRights(
//
//	LSA_HANDLE          PolicyHandle,
//	PSID                AccountSid,
//	PLSA_UNICODE_STRING *UserRights,
//	PULONG              CountOfRights
//
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountrights
func LsaEnumerateAccountRights(hPolicy syscall.Handle, sid *syscall.SID) ([]string, error) {
	var rights uintptr
	var count uint32
	status, _, _ := lsaEnumerateAccountRights.Call(
		uintptr(hPolicy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&rights)),
		uintptr(unsafe.Pointer(&count)),
	)
	if status != _STATUS_SUCCESS {
		errno := LsaNtStatusToWinError(status)
		if errno == syscall.ERROR_FILE_NOT_FOUND { // user has no rights assigned
			return nil, nil
		}
		return nil, errno
	}
	defer LsaFreeMemory(rights)
	var userRights []string
	rs := (*[1 << 16]_LSA_UNICODE_STRING)(unsafe.Pointer(rights))[:count:count] //nolint
	for _, r := range rs {
		userRights = append(userRights, UTF16PtrToStringN((*uint16)(r.Buffer), int(r.Length/2)))
	}
	return userRights, nil
}

// NTSTATUS LsaEnumerateAccountsWithUserRight(
//
//	[in]  LSA_HANDLE          PolicyHandle,
//	[in]  PLSA_UNICODE_STRING UserRight,
//	[out] PVOID               *Buffer,
//	[out] PULONG              CountReturned
//
// );
// https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumerateaccountswithuserright
func LsaEnumerateAccountsWithUserRight(hPolicy syscall.Handle, userright string) ([]windowssecurity.SID, error) {
	var bufferptr uintptr
	var count uint32
	lsaStr := toLSAUnicodeString(userright)
	status, _, _ := lsaEnumerateAccountsWithUserRight.Call(
		uintptr(hPolicy),
		uintptr(unsafe.Pointer(&lsaStr)),
		uintptr(unsafe.Pointer(&bufferptr)),
		uintptr(unsafe.Pointer(&count)),
	)
	if status != _STATUS_SUCCESS {
		errno := LsaNtStatusToWinError(status)
		if errno == syscall.ERROR_FILE_NOT_FOUND { // user has no rights assigned
			return nil, nil
		}
		return nil, errno
	}
	defer LsaFreeMemory(bufferptr)

	var users []windowssecurity.SID

	for i := 0; i < int(count); i++ {
		nativesid := ((*[32768]uintptr)(unsafe.Pointer(bufferptr)))[i]
		sid, err := windowssecurity.SIDFromPtr(nativesid)
		if err != nil {
			return nil, err
		}
		users = append(users, sid)
	}
	return users, nil
}

// NTSTATUS LsaAddAccountRights(
//
//	LSA_HANDLE          PolicyHandle,
//	PSID                AccountSid,
//	PLSA_UNICODE_STRING UserRights,
//	ULONG               CountOfRights
//
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights
func LsaAddAccountRights(hPolicy syscall.Handle, sid *syscall.SID, rights []string) error {
	var lsaRights []_LSA_UNICODE_STRING
	for _, r := range rights {
		lsaRights = append(lsaRights, toLSAUnicodeString(r))
	}
	status, _, _ := lsaAddAccountRights.Call(
		uintptr(hPolicy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&lsaRights[0])),
		uintptr(len(rights)),
	)
	if status != _STATUS_SUCCESS {
		return LsaNtStatusToWinError(status)
	}
	return nil
}

// NTSTATUS LsaRemoveAccountRights(
//
//	LSA_HANDLE          PolicyHandle,
//	PSID                AccountSid,
//	BOOLEAN             AllRights,
//	PLSA_UNICODE_STRING UserRights,
//	ULONG               CountOfRights
//
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights
func LsaRemoveAccountRights(hPolicy syscall.Handle, sid *syscall.SID, removeAll bool, rights []string) error {
	var lsaRights []_LSA_UNICODE_STRING
	if !removeAll {
		for _, r := range rights {
			lsaRights = append(lsaRights, toLSAUnicodeString(r))
		}
	}
	status, _, _ := lsaRemoveAccountRights.Call(
		uintptr(hPolicy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(toBOOL(removeAll)),
		uintptr(unsafe.Pointer(&lsaRights[0])),
		uintptr(len(lsaRights)),
	)
	if status != _STATUS_SUCCESS {
		return LsaNtStatusToWinError(status)
	}
	return nil
}

// ULONG LsaNtStatusToWinError(
//
//	NTSTATUS Status
//
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsantstatustowinerror
func LsaNtStatusToWinError(status uintptr) error {
	ret, _, _ := lsaNtStatusToWinError.Call(status)
	if ret == ERROR_MR_MID_NOT_FOUND {
		return syscall.EINVAL
	}
	return syscall.Errno(ret)
}

// NTSTATUS LsaFreeMemory(
//
//	PVOID Buffer
//
// );
// https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/nf-ntsecapi-lsafreememory
func LsaFreeMemory(buf uintptr) error {
	status, _, _ := lsaFreeMemory.Call(buf)
	if status == _STATUS_SUCCESS {
		return nil
	}
	return LsaNtStatusToWinError(status)
}

func EnumerateAccountRights(s *syscall.SID) ([]string, error) {
	sid := (*syscall.SID)(unsafe.Pointer(s))
	phPolicy, err := LsaOpenPolicy("", _POLICY_READ)
	if err != nil {
		return nil, errors.Wrapf(err, "lsaOpenPolicy")
	}
	defer LsaClose(*phPolicy)
	rights, err := LsaEnumerateAccountRights(*phPolicy, sid)
	if err != nil {
		str, _ := sid.String()
		return nil, errors.Wrapf(err, "lsaEnumerateAccountRights(%s)", str)
	}
	return rights, nil
}

func toBOOL(b bool) BOOL {
	if b {
		return TRUE
	}
	return FALSE
}

func (b BOOL) boolean() bool {
	if b == TRUE {
		return true
	}
	return false
}

// UTF16PtrToStringN converts a UTF-16 encoded C-String
// into a Go string. The n specifies the length of the string.
// This function supports only wide-character strings in UTF-16; not UTF-8.
func UTF16PtrToStringN(wstr *uint16, n int) string {
	if wstr != nil {
		us := make([]uint16, 0, n)
		i := 0
		for p := uintptr(unsafe.Pointer(wstr)); ; p += 2 {
			//nolint
			u := *(*uint16)(unsafe.Pointer(p))
			us = append(us, u)
			i++
			if i > n {
				return string(utf16.Decode(us))
			}
		}
	}
	return ""
}
