package windowssecurity

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func GetOwnerAndDACL(objectName string, objectType SE_OBJECT_TYPE) (SID, []byte, error) {
	var sid *windows.SID
	var dacl []byte
	sd, err := windows.GetNamedSecurityInfo(objectName, windows.SE_OBJECT_TYPE(objectType), windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		sid, _, err = sd.Owner()
		if err == nil {
			var nativedacl *windows.ACL
			nativedacl, _, err = sd.DACL()
			if err == nil {
				revision := (*[8]uint8)(unsafe.Pointer(nativedacl))[0]
				if revision != 1 && revision != 2 && revision != 4 {
					// Wrong version
					err = fmt.Errorf("Only DACL version 1, 2 and 4 is supported. If you see this, please report that you encountered a version %v ACL!", revision)
				} else if (*[8]uint8)(unsafe.Pointer(nativedacl))[1] != 0 {
					// Sbz1 should be zero
					err = errors.New("Sbz1 is nonzero")
				} else if (*[8]uint16)(unsafe.Pointer(nativedacl))[3] != 0 {
					// Sbz2 should also be zero
					err = errors.New("Sbz2 is nonzero")
				} else {
					// Absolutely horrendous, but I don't see any other way - see windows.DACL definition
					dacllength := (*[2]uint16)(unsafe.Pointer(nativedacl))[1]
					if dacllength != 0 {
						// We'd have crashed already
						dacl = make([]byte, dacllength)
						copy(dacl, (*[0x7fff0000]byte)(unsafe.Pointer(nativedacl))[:dacllength:dacllength])
					}
				}
			}
		}
	}

	var oursid SID
	if err == nil {
		oursid, err = ParseStringSID(sid.String())
	}
	return oursid, dacl, err
}
