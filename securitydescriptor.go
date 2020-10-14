package main

import (
	"encoding/binary"
	"errors"
	"log"
	"strings"

	"github.com/gofrs/uuid"
)

type SecurityDescriptor struct {
	Control SecurityDescriptorControlFlag
	Owner   SID
	Group   SID
	SACL    ACL
	DACL    ACL
}

type ACL struct {
	Revision byte
	// Type     uint16
	// Flags    uint16
	Entries []ACE
}

type ACE struct {
	Type                byte
	ACEFlags            byte
	Mask                uint32
	SID                 SID
	Flags               uint32
	ObjectType          uuid.UUID
	InheritedObjectType uuid.UUID
}

func ParseSecurityDescriptor(data []byte) (SecurityDescriptor, error) {
	var result SecurityDescriptor
	if len(data) < 20 {
		return SecurityDescriptor{}, errors.New("Not enough data")
	}
	if data[0] != 1 {
		return SecurityDescriptor{}, errors.New("Unknown Revision")
	}
	if data[1] != 0 {
		return SecurityDescriptor{}, errors.New("Unknown Sbz1")
	}
	result.Control = SecurityDescriptorControlFlag(binary.LittleEndian.Uint16(data[2:4]))
	OffsetOwner := binary.LittleEndian.Uint32(data[4:8])
	if result.Control&CONTROLFLAG_OWNER_DEFAULTED == 0 && OffsetOwner == 0 {
		log.Printf("Warning: ACL has no owner, and does not default")
	}
	OffsetGroup := binary.LittleEndian.Uint32(data[8:12])
	if result.Control&CONTROLFLAG_GROUP_DEFAULTED == 0 && OffsetGroup == 0 {
		log.Printf("Warning: ACL has no group, and does not default")
	}
	OffsetSACL := binary.LittleEndian.Uint32(data[12:16])
	if result.Control&CONTROLFLAG_SACL_PRESENT != 0 && OffsetSACL == 0 {
		log.Printf("Warning: ACL has no SACL, but claims to have it")
	}
	OffsetDACL := binary.LittleEndian.Uint32(data[16:20])
	if result.Control&CONTROLFLAG_DACL_PRESENT != 0 && OffsetDACL == 0 {
		log.Printf("Warning: ACL has no DACL, but claims to have it")
	}
	var err error
	if OffsetOwner > 0 {
		result.Owner, _, err = ParseSID(data[OffsetOwner:])
		if err != nil {
			return result, err
		}
	}
	if OffsetGroup > 0 {
		result.Group, _, err = ParseSID(data[OffsetGroup:])
		if err != nil {
			return result, err
		}
	}
	if OffsetSACL > 0 {
		result.SACL, err = parseACL(data[OffsetSACL:])
		if err != nil {
			return result, err
		}
	}
	if OffsetDACL > 0 {
		result.DACL, err = parseACL(data[OffsetDACL:])
		if err != nil {
			return result, err
		}
	}

	return result, nil
}

func (sd SecurityDescriptor) String() string {
	var result string
	var flags []string
	if sd.Control&CONTROLFLAG_OWNER_DEFAULTED != 0 {
		flags = append(flags, "OWNER_DEFAULTED")
	}
	if sd.Control&CONTROLFLAG_GROUP_DEFAULTED != 0 {
		flags = append(flags, "GROUP_DEFAULTED")
	}
	if sd.Control&CONTROLFLAG_DACL_PRESENT != 0 {
		flags = append(flags, "DACL_PRESENT")
	}
	if sd.Control&CONTROLFLAG_DACL_DEFAULTED != 0 {
		flags = append(flags, "DACL_DEFAULTED")
	}
	if sd.Control&CONTROLFLAG_SACL_PRESENT != 0 {
		flags = append(flags, "SACL_PRESENT")
	}
	if sd.Control&CONTROLFLAG_SACL_DEFAULTED != 0 {
		flags = append(flags, "SACL_DEFAULTED")
	}
	if sd.Control&CONTROLFLAG_DACL_AUTO_INHERITED != 0 {
		flags = append(flags, "DACL_AUTO_INHERITED")
	}
	if sd.Control&CONTROLFLAG_SACL_AUTO_INHERITED != 0 {
		flags = append(flags, "SACL_AUTO_INHERITED")
	}
	if sd.Control&CONTROLFLAG_DACL_PROTECTED != 0 {
		flags = append(flags, "DACL_PROTECTED")
	}
	if sd.Control&CONTROLFLAG_SACL_PROTECTED != 0 {
		flags = append(flags, "SACL_PROTECTED")
	}
	result = "SecurityDescriptor: " + strings.Join(flags, " | ") + "\n"
	if !sd.Owner.IsNull() {
		result += "Owner: " + sd.Owner.String() + "\n"
	}
	if !sd.Group.IsNull() {
		result += "Group: " + sd.Group.String() + "\n"
	}
	if sd.Control&CONTROLFLAG_DACL_PRESENT != 0 {
		result += "DACL:\n" + sd.DACL.String()
	}
	if sd.Control&CONTROLFLAG_SACL_PRESENT != 0 {
		result += "DACL:\n" + sd.SACL.String()
	}
	return result
}
