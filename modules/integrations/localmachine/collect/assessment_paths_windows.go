package collect

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"golang.org/x/sys/windows"
)

// Inspect without following reparse points. Identity and ACL are copied from the
// same handle; a later pathname replacement cannot mix two different objects.
func inspectAssessmentPath(configured string) lm.PathSecurity {
	path := filepath.Clean(resolvepath(configured))
	r := lm.PathSecurity{ConfiguredPath: configured, Path: path, InspectionPath: path, IdentityResult: basedata.CollectionResult{Status: basedata.CollectionNotRequested}}
	fail := func(err error) lm.PathSecurity {
		r.Result = nativeCollectionResult(err)
		if r.FileID == "" {
			r.IdentityResult = r.Result
		}
		return r
	}
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) || strings.Contains(path, "%") || strings.Contains(strings.TrimPrefix(path, filepath.VolumeName(path)), ":") {
		r.Result = basedata.CollectionResult{Status: basedata.CollectionUnsupported, ErrorCode: "non_local_path"}
		return r
	}
	// Check each ancestor. Keep handles open without delete sharing while the leaf
	// is opened, preventing ordinary rename/replacement of checked directories.
	var ancestors []windows.Handle
	defer func() {
		for _, h := range ancestors {
			windows.CloseHandle(h)
		}
	}()
	volume := filepath.VolumeName(path)
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return fail(err)
	}
	if windows.GetDriveType(root) == windows.DRIVE_REMOTE {
		r.Result = basedata.CollectionResult{Status: basedata.CollectionUnsupported, ErrorCode: "remote_drive"}
		return r
	}
	parts := strings.Split(strings.TrimPrefix(path[len(volume):], `\`), `\`)
	if len(parts) > 256 {
		return fail(errAssessmentLimit)
	}
	prefix := volume + `\`
	for i, part := range parts {
		if part != "" {
			prefix = filepath.Join(prefix, part)
		}
		leaf := i == len(parts)-1
		access := uint32(windows.FILE_READ_ATTRIBUTES)
		if leaf {
			access |= windows.READ_CONTROL
		}
		p, err := windows.UTF16PtrFromString(prefix)
		if err != nil {
			return fail(err)
		}
		h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return fail(err)
		}
		ancestors = append(ancestors, h)
		var identity windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &identity); err != nil {
			r.IdentityResult = nativeCollectionResult(err)
			return fail(err)
		}
		if identity.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			r.ReparsePoint, r.ReparseAt = true, prefix
			r.Result = basedata.CollectionResult{Status: basedata.CollectionUnsupported, ErrorCode: "reparse_not_followed"}
			return r
		}
		if !leaf {
			continue
		}
		r.FileID = fmt.Sprintf("%016x", uint64(identity.FileIndexHigh)<<32|uint64(identity.FileIndexLow))
		r.VolumeSerial = fmt.Sprintf("%08x", identity.VolumeSerialNumber)
		buf := make([]uint16, 32768)
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err == nil && n >= uint32(len(buf)) {
			err = errAssessmentLimit
		}
		r.IdentityResult = nativeCollectionResult(err)
		if err != nil {
			return fail(err)
		}
		r.FinalPath = windows.UTF16ToString(buf[:n])
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return fail(err)
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return fail(err)
		}
		if owner != nil {
			r.Owner = owner.String()
		}
		acl, _, err := sd.DACL()
		if err != nil {
			return fail(err)
		}
		if acl == nil {
			r.NullDACL = true
		} else {
			// ACL header's second uint16 is its total byte length.
			size := (*[2]uint16)(unsafe.Pointer(acl))[1]
			if size < 8 {
				return fail(windows.ERROR_INVALID_ACL)
			}
			r.DACL = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(acl)), int(size))...)
		}
		r.Result = nativeCollectionResult(nil)
	}
	return r
}
