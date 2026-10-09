//go:build windows

package collect

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"golang.org/x/sys/windows"
)

var errNoProcessIdentity = errors.New("process has no identity")

// A process that exited after the snapshot cannot be opened and is reported
// as not found; neither it nor the idle pseudo-process is a collection failure.
func processIdentityResult(err error) basedata.CollectionResult {
	switch {
	case errors.Is(err, errNoProcessIdentity):
		return basedata.CollectionResult{Status: basedata.CollectionNotFound, ErrorCode: "pseudo_process"}
	case errors.Is(err, windows.ERROR_INVALID_PARAMETER):
		return basedata.CollectionResult{Status: basedata.CollectionNotFound, ErrorCode: "process_exited"}
	}
	return nativeCollectionResult(err)
}

var (
	sessionDLL       = windows.NewLazySystemDLL("secur32.dll")
	enumerateLogons  = sessionDLL.NewProc("LsaEnumerateLogonSessions")
	getLogonData     = sessionDLL.NewProc("LsaGetLogonSessionData")
	freeLogonData    = sessionDLL.NewProc("LsaFreeReturnBuffer")
	logonStatusError = windows.NewLazySystemDLL("advapi32.dll").NewProc("LsaNtStatusToWinError")
)

// Prefix of SECURITY_LOGON_SESSION_DATA. The larger native allocation owns all
// pointers. Only identity/session metadata is copied before releasing it.
// Pointer-sized fields follow the calling process ABI, including under WOW64.
// The prefix ends at byte 56 on 386 and byte 88 on amd64.
type logonDataPrefix struct {
	Size                         uint32
	ID                           windows.LUID
	User, Domain, Authentication windows.NTUnicodeString
	Type, Session                uint32
	SID                          *windows.SID
	Time                         windows.Filetime
}

func logonID(low uint32, high int32) string {
	return fmt.Sprintf("%016x", uint64(uint32(high))<<32|uint64(low))
}

func collectCurrentSessions(c *assessmentCapture) error {
	c.data.Scope = "local-logon-sessions-at-capture;not-proof-of-credentials"
	for _, proc := range []*windows.LazyProc{enumerateLogons, getLogonData, freeLogonData, logonStatusError} {
		if proc.Find() != nil {
			return errors.ErrUnsupported
		}
	}
	var count uint32
	var list *windows.LUID
	status, _, _ := enumerateLogons.Call(uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list)))
	if status != 0 {
		code, _, _ := logonStatusError.Call(status)
		return syscall.Errno(code)
	}
	defer freeLogonData.Call(uintptr(unsafe.Pointer(list)))
	if count > 10000 {
		return errAssessmentLimit
	}
	if count > 0 && list == nil {
		return errors.ErrUnsupported
	}
	var sessions *windows.WTS_SESSION_INFO
	var sessionCount uint32
	states := map[uint32]uint32{}
	wtsErr := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &sessionCount)
	if wtsErr == nil {
		if sessionCount > 10000 {
			windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
			return errAssessmentLimit
		}
		if sessions != nil {
			for _, session := range unsafe.Slice(sessions, sessionCount) {
				states[session.SessionID] = session.State
			}
		}
		windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	}
	if err := c.operation("terminal-session-states", wtsErr); err != nil {
		return err
	}
	for _, id := range unsafe.Slice(list, count) {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		var data *logonDataPrefix
		status, _, _ := getLogonData.Call(uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&data)))
		r := map[string]any{"LogonID": logonID(id.LowPart, id.HighPart), "ObservedAt": time.Now().UTC()}
		if status != 0 {
			code, _, _ := logonStatusError.Call(status)
			err := syscall.Errno(code)
			r["Result"] = nativeCollectionResult(err)
			c.failure(nativeCollectionResult(err))
		} else if data == nil {
			r["Result"] = nativeCollectionResult(errors.ErrUnsupported)
			c.failure(nativeCollectionResult(errors.ErrUnsupported))
		} else {
			func() {
				defer freeLogonData.Call(uintptr(unsafe.Pointer(data)))
				if err := data.appendMetadata(r); err != nil {
					r["Result"] = nativeCollectionResult(err)
					c.failure(nativeCollectionResult(err))
					return
				}
				r["Result"] = nativeCollectionResult(nil)
				if state, ok := states[data.Session]; ok {
					r["TerminalState"] = state
				}
			}()
		}
		if err := c.add(r); err != nil {
			return err
		}
	}
	return nil
}

// Copy metadata while the native allocation and its referenced strings are alive.
func (data *logonDataPrefix) appendMetadata(record map[string]any) error {
	if data == nil || data.Size < uint32(unsafe.Sizeof(logonDataPrefix{})) {
		return errors.ErrUnsupported
	}
	for _, value := range []*windows.NTUnicodeString{&data.User, &data.Domain, &data.Authentication} {
		if value.Length%2 != 0 || value.Length > value.MaximumLength || (value.Length != 0 && value.Buffer == nil) {
			return errors.ErrUnsupported
		}
	}
	record["User"], record["Domain"], record["AuthenticationPackage"] = data.User.String(), data.Domain.String(), data.Authentication.String()
	record["LogonType"], record["SessionID"] = data.Type, data.Session
	if data.SID != nil && data.SID.IsValid() {
		record["SID"] = data.SID.String()
	}
	if data.Time.HighDateTime != 0 {
		record["LogonTime"] = time.Unix(0, data.Time.Nanoseconds()).UTC()
	}
	return nil
}

func collectProcessIdentities(c *assessmentCapture) error {
	c.data.Scope = "local-process-snapshot;no-command-lines-or-environment"
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(snapshot, &entry)
	for count := 0; err == nil; count++ {
		if count >= 10000 {
			return errAssessmentLimit
		}
		if err := c.ctx.Err(); err != nil {
			return err
		}
		r := map[string]any{"PID": entry.ProcessID, "ParentPID": entry.ParentProcessID, "Name": windows.UTF16ToString(entry.ExeFile[:]), "ObservedAt": time.Now().UTC()}
		identityErr := func() error {
			if entry.ProcessID == 0 {
				return errNoProcessIdentity // The idle pseudo-process has no token.
			}
			handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
			if err != nil {
				return err
			}
			defer windows.CloseHandle(handle)
			var token windows.Token
			if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
				return err
			}
			defer token.Close()
			user, err := token.GetTokenUser()
			if err != nil {
				return err
			}
			r["SID"] = user.User.Sid.String()
			var session uint32
			if sessionErr := windows.ProcessIdToSessionId(entry.ProcessID, &session); sessionErr == nil {
				r["SessionID"] = session
			} else {
				r["SessionResult"] = nativeCollectionResult(sessionErr)
			}
			var required uint32
			buffer := make([]byte, 128)
			err = windows.GetTokenInformation(token, windows.TokenStatistics, &buffer[0], uint32(len(buffer)), &required)
			if err == nil && required >= 16 {
				r["LogonID"] = logonID(binary.LittleEndian.Uint32(buffer[8:12]), int32(binary.LittleEndian.Uint32(buffer[12:16])))
			}
			r["LogonIDResult"] = nativeCollectionResult(err)
			return nil
		}()
		result := processIdentityResult(identityErr)
		r["Result"] = result
		if result.Status != basedata.CollectionCollected && result.Status != basedata.CollectionNotFound {
			c.failure(result)
		}
		if err := c.add(r); err != nil {
			return err
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil
	}
	return err
}
