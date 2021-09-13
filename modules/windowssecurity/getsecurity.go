package windowssecurity

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func GetOwnerAndDACL(objectName string, objectType windows.SE_OBJECT_TYPE) (*windows.SID, []byte, error) {
	var sid *windows.SID
	var dacl []byte
	sd, err := windows.GetNamedSecurityInfo(objectName, objectType, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		sid, _, err = sd.Owner()
		if err == nil {
			nativedacl, _, err := sd.DACL()
			if err == nil {
				// Absolutely horrendous, but I don't see any other way - see windows.DACL definition
				dacllength := (*[2]uint16)(unsafe.Pointer(&nativedacl))[1]
				if dacllength != 0 {
					// We'd have crashed already
					dacl = make([]byte, dacllength)
					copy(dacl, (*[0x7fff0000]byte)(unsafe.Pointer(&dacl))[:dacllength:dacllength])
				}
			}
		}
	}
	return sid, dacl, err
}
