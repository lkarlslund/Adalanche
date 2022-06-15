package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/rs/zerolog/log"
)

type SecurityDescriptorControlFlag uint16
type ACLPermissionMask uint32

// http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm

const (
	CONTROLFLAG_OWNER_DEFAULTED     SecurityDescriptorControlFlag = 0x0001
	CONTROLFLAG_GROUP_DEFAULTED     SecurityDescriptorControlFlag = 0x0002
	CONTROLFLAG_DACL_PRESENT                                      = 0x0004
	CONTROLFLAG_DACL_DEFAULTED                                    = 0x0008
	CONTROLFLAG_SACL_PRESENT                                      = 0x0010
	CONTROLFLAG_SACL_DEFAULTED                                    = 0x0020
	CONTROLFLAG_DACL_AUTO_INHERITED                               = 0x0400
	CONTROLFLAG_SACL_AUTO_INHERITED                               = 0x0800
	CONTROLFLAG_DACL_PROTECTED                                    = 0x1000
	CONTROLFLAG_SACL_PROTECTED                                    = 0x2000
	CONTROLFLAG_SELF_RELATIVE                                     = 0x8000

	// ACE.Type
	ACETYPE_ACCESS_ALLOWED        = 0x00
	ACETYPE_ACCESS_DENIED         = 0x01
	ACETYPE_ACCESS_ALLOWED_OBJECT = 0x05
	ACETYPE_ACCESS_DENIED_OBJECT  = 0x06

	// ACE.ACEFlags
	ACEFLAG_INHERIT_ACE              = 0x02 // Child objects inherit this ACE
	ACEFLAG_NO_PROPAGATE_INHERIT_ACE = 0x04 // Only the NEXT child inherits this, not further down the line
	ACEFLAG_INHERIT_ONLY_ACE         = 0x08 // Not valid for this object, only for children
	ACEFLAG_INHERITED_ACE            = 0x10 // This ACE was interited from parent object

	// ACE.Flags - present if this is a ACETYPE_ACCESS_*_OBJECT Type
	OBJECT_TYPE_PRESENT           = 0x01
	INHERITED_OBJECT_TYPE_PRESENT = 0x02

	RIGHT_MAXIMUM_ALLOWED = 0x02000000 /* Not stored in AD, just for requests */

	RIGHT_ACCESS_SYSTEM_SECURITY = 0x01000000 /* Not stored in AD, just for requests */

	// REGISTRY PERMISSIONS MASK
	KEY_ALL_ACCESS         = 0xF003F
	KEY_READ               = 0x20019
	KEY_WRITE              = 0x20006
	KEY_EXECUTE            = 0x20019
	KEY_CREATE_SUB_KEYS    = 0x0004
	KEY_ENUMERATE_SUB_KEYS = 0x0008
	KEY_NOTIFY             = 0x0010
	KEY_QUERY_VALUE        = 0x0001
	KEY_SET_VALUE          = 0x0002

	// FILE PERMISSIONS

	FILE_READ_DATA        = 0x00000001 // Grants the right to read data from the file.
	FILE_LIST_DIRECTORY   = 0x00000001 // Grants the right to read data from the file. For a directory, this value grants the right to list the contents of the directory.
	FILE_WRITE_DATA       = 0x00000002 // Grants the right to write data to the file.
	FILE_ADD_FILE         = 0x00000002 // Grants the right to write data to the file. For a directory, this value grants the right to create a file in the directory.
	FILE_APPEND_DATA      = 0x00000004 // Grants the right to append data to the file. For a directory, this value grants the right to create a subdirectory.
	FILE_ADD_SUBDIRECTORY = 0x00000004 // Grants the right to append data to the file. For a directory, this value grants the right to create a subdirectory.
	FILE_READ_EA          = 0x00000008 // Grants the right to read extended attributes.
	FILE_WRITE_EA         = 0x00000010 // Grants the right to write extended attributes.
	FILE_EXECUTE          = 0x00000020 // Grants the right to execute a file.
	FILE_TRAVERSE         = 0x00000020 // Grants the right to execute a file. For a directory, the directory can be traversed.
	FILE_DELETE_CHILD     = 0x00000040 // Grants the right to delete a directory and all the files it contains (its children), even if the files are read-only.
	FILE_READ_ATTRIBUTES  = 0x00000080 // Grants the right to read file attributes.
	FILE_WRITE_ATTRIBUTES = 0x00000100 // Grants the right to change file attributes.
	DELETE                = 0x00010000 // Grants the right to delete the object.
	READ_CONTROL          = 0x00020000 // Grants the right to read the information in the security descriptor for the object, not including the information in the SACL.
	WRITE_DAC             = 0x00040000 // Grants the right to modify the DACL in the object security descriptor for the object.
	WRITE_OWNER           = 0x00080000 // Grants the right to change the owner in the security descriptor for the object.
	SYNCHRONIZE           = 0x00100000
)

var (
	NullGUID = uuid.UUID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

/*
Extended rights:

ab721a53-1e2f-11d0-9819-00aa0040529b = change pwd
00299570-246d-11d0-a768-00aa006e0529 = force reset pwd
1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes
1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes-All

Properties:

bf9679c0-0de6-11d0-a285-00aa003049e2 = member property for groups
f30e3bc1-9ff0-11d1-b603-0000f80367c1 = GPC-File-Sys-Path
ms-Mcs-AdmPwd reading

*/

func ParseACL(data []byte) (ACL, error) {
	var acl ACL
	if len(data) < 8 {
		return acl, errors.New("not enough data to be an ACL")
	}
	acl.Revision = data[0]
	if acl.Revision != 1 && acl.Revision != 2 && acl.Revision != 4 {
		return acl, fmt.Errorf("unsupported ACL revision %v", acl.Revision)
	}
	if data[1] != 0 {
		return acl, errors.New("bad Sbz1")
	}
	aclsize := int(binary.LittleEndian.Uint16(data[2:4]))
	if aclsize > len(data) {
		return acl, errors.New("the ACL size exceeds available data")
	}
	aclcount := int(binary.LittleEndian.Uint16(data[4:6]))
	if data[6] != 0 {
		return acl, errors.New("bad Sbz2")
	}

	acledata := data[8:]

	acl.Entries = make([]ACE, aclcount)

	for i := 0; i < aclcount; i++ {
		var err error
		var ace ACE
		ace, acledata, err = ParseACLentry(acledata)
		if ace.Type == ACETYPE_ACCESS_DENIED || ace.Type == ACETYPE_ACCESS_DENIED_OBJECT {
			acl.containsdeny = true
		}
		if err != nil {
			return acl, err
		}
		acl.Entries[i] = ace
	}

	return acl, nil
}

func (a ACL) String(ao *Objects) string {
	result := fmt.Sprintf("ACL revision %v:\n", a.Revision)
	for _, ace := range a.Entries {
		result += "ACE: " + ace.String(ao) + "\n"
	}
	return result
}

func ParseACLentry(odata []byte) (ACE, []byte, error) {
	var ace ACE
	var err error
	// ACEHEADER
	data := odata
	ace.Type = data[0]
	ace.ACEFlags = data[1]
	acesize := binary.LittleEndian.Uint16(data[2:])
	ace.Mask = ACLPermissionMask(binary.LittleEndian.Uint32(data[4:]))

	data = data[8:]
	if ace.Type == ACETYPE_ACCESS_ALLOWED_OBJECT || ace.Type == ACETYPE_ACCESS_DENIED_OBJECT {
		ace.Flags = binary.LittleEndian.Uint32(data[0:])
		data = data[4:]
		if ace.Flags&OBJECT_TYPE_PRESENT != 0 {
			ace.ObjectType, err = uuid.FromBytes(data[0:16])
			if err != nil {
				return ace, data, err
			}
			ace.ObjectType = util.SwapUUIDEndianess(ace.ObjectType)
			data = data[16:]
		}
		if ace.Flags&INHERITED_OBJECT_TYPE_PRESENT != 0 {
			ace.InheritedObjectType, err = uuid.FromBytes(data[0:16])
			if err != nil {
				return ace, data, err
			}
			ace.InheritedObjectType = util.SwapUUIDEndianess(ace.InheritedObjectType)
			data = data[16:]
		}
	}

	ace.SID, data, err = windowssecurity.ParseSID(data)
	if err != nil {
		return ace, data, err
	}
	return ace, odata[acesize:], nil
}

func (a ACL) AllowObjectClass(index int, o *Object, mask ACLPermissionMask, g uuid.UUID, ao *Objects) bool {
	if a.Entries[index].checkObjectClass(true, o, mask, g, ao) {
		if a.containsdeny {
			// See if a prior one denies it
			for i := 0; i < index; i++ {
				// Check SID first, this is very fast, then do detailed check later
				if a.Entries[i].Type != ACETYPE_ACCESS_DENIED && a.Entries[i].Type != ACETYPE_ACCESS_DENIED_OBJECT {
					// this is not a DENY ACE, so we can skip it
					continue
				}

				var sidmatch bool
				checksid := a.Entries[index].SID
				for _, sid := range o.MemberOfSID(true) {
					if sid == checksid {
						sidmatch = true
						break
					}
				}

				if sidmatch && a.Entries[i].checkObjectClass(false, o, mask, g, ao) {
					if a.Entries[i].ObjectType != NullGUID {
						if g == NullGUID {
							// We tested for all properties / extended rights, but the DENY blocks some of these
							// log.Debug().Msgf("ACL allow/deny detection: %v denies that %v allows", a.Entries[i].String(), a.Entries[index].String())
							return false
						}
						if a.Entries[i].ObjectType == g {
							// The DENY is specific to attributes / extended rights etc. so it only blocks if the requested is the same
							// log.Debug().Msgf("ACL allow/deny detection: %v denies that %v allows", a.Entries[i].String(), a.Entries[index].String())
							return false
						}
					}
				}
			}
		}
		return true // No deny match
	}
	return false // No allow match
}

var objectSecurityGUIDcacheLock sync.RWMutex
var objectSecurityGUIDcache = make(map[uuid.UUID]uuid.UUID)

// Is the ACE something that allows or denies this type of GUID?
func (a ACE) checkObjectClass(allow bool, o *Object, mask ACLPermissionMask, g uuid.UUID, ao *Objects) bool {
	// http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm
	// Don't to drugs while reading the above ^^^^^

	if a.ACEFlags&ACEFLAG_INHERIT_ONLY_ACE != 0 {
		// Only for child objects, not for this one
		return false
	}

	if mask != 0 && a.Mask&mask != mask {
		return false
	}

	if a.ObjectType != NullGUID {
		// Only some attributes, extended rights or whatever apply
		typematch := a.ObjectType == g
		if !typematch {
			// Lets chack if this requested guid is part of a group which is allowed
			if threadsafeobject != 0 {
				objectSecurityGUIDcacheLock.RLock()
			}
			cachedset, found := objectSecurityGUIDcache[g]
			if threadsafeobject != 0 {
				objectSecurityGUIDcacheLock.RUnlock()
			}
			if !found {
				// Not in cache, let's populate it
				if s, found := ao.Find(SchemaIDGUID, AttributeValueGUID(g)); found {
					if set, ok := s.OneAttrRaw(AttributeSecurityGUID).(uuid.UUID); ok {
						cachedset = set
						if cachedset == NullGUID {
							cachedset = UnknownGUID // Just to be sure
						}

						if threadsafeobject != 0 {
							objectSecurityGUIDcacheLock.Lock()
						}
						objectSecurityGUIDcache[g] = cachedset
						if threadsafeobject != 0 {
							objectSecurityGUIDcacheLock.Unlock()
						}
					}
				}
			}
			if a.ObjectType == cachedset {
				typematch = true
			}
		}
		if !typematch {
			return false
		}
	}

	if (allow && a.Type == ACETYPE_ACCESS_ALLOWED) || (!allow && a.Type == ACETYPE_ACCESS_DENIED) {
		// All objects allowed
		return true
	}

	if (allow && a.Type == ACETYPE_ACCESS_ALLOWED_OBJECT) || (!allow && a.Type == ACETYPE_ACCESS_DENIED_OBJECT) {

		// Only some object classes
		if a.Flags&INHERITED_OBJECT_TYPE_PRESENT == 0 {
			// Only this object
			return true
		}

		if a.InheritedObjectType == NullGUID {
			// It's an allow only this class NULL (all object types)
			log.Warn().Msgf("ACE indicates allowed object, but is actually allowing all kinds through null GUID")
			return true
		}

		// We weren't passed a type, so if we don't have general access return false
		if o == nil {
			return false
		}

		for _, classattr := range o.Attr(ObjectClassGUIDs).Slice() {
			if class, ok := classattr.Raw().(uuid.UUID); ok {
				if a.InheritedObjectType == class {
					return true
				}
			}
		}
	}

	return false
}

func (a ACE) String(ao *Objects) string {
	var result string
	switch a.Type {
	case ACETYPE_ACCESS_ALLOWED:
		result += "Allow"
	case ACETYPE_ACCESS_ALLOWED_OBJECT:
		result += "Allow object"
	case ACETYPE_ACCESS_DENIED:
		result += "Deny"
	case ACETYPE_ACCESS_DENIED_OBJECT:
		result += "Deny object"
	default:
		result += fmt.Sprintf("Unknown %v", a.ACEFlags)
	}

	result += " " + a.SID.String()

	if a.Flags&OBJECT_TYPE_PRESENT != 0 {
		// log.Debug().Msgf("Looking for right %v", a.ObjectType)
		av := AttributeValueGUID(a.ObjectType)
		if ao != nil {
			if o, found := ao.Find(RightsGUID, av); found {
				result += fmt.Sprintf(" RIGHT %v (%v)", o.OneAttr(Name), a.ObjectType)
			} else if o, found := ao.Find(SchemaIDGUID, av); found {
				result += fmt.Sprintf(" CLASS or ATTRIBUTE %v (%v)", o.OneAttr(Name), a.ObjectType)
			} else if o, found := ao.FindGUID(a.ObjectType); found {
				result += fmt.Sprintf(" OBJECT? %v (%v)", o.OneAttr(Description), a.ObjectType)
			} else {
				result += " " + a.ObjectType.String() + " (not found)"
			}
		} else {
			result += " " + a.ObjectType.String() + " (schema inaccessible)"
		}

	}
	if a.Flags&INHERITED_OBJECT_TYPE_PRESENT != 0 {
		// log.Debug().Msgf("Looking for right %v", a.InheritedObjectType)
		// if o, found := AllRights[a.InheritedObjectType]; found {
		// 	result += fmt.Sprintf(" inherited RIGHT %v (%v)", o.OneAttr(Name), a.InheritedObjectType)
		// } else
		if ao != nil {
			if o, found := ao.Find(SchemaIDGUID, AttributeValueGUID(a.InheritedObjectType)); found {
				result += fmt.Sprintf(" inherited CLASS %v (%v)", o.OneAttr(Name), a.InheritedObjectType)
				// }
				//  else if o, found := AllSchemaAttributes[a.InheritedObjectType]; found {
				// 	result += fmt.Sprintf(" inherited ATTRIBUTE %v (%v)", o.OneAttr(Name), a.InheritedObjectType)
				// } else if o, found := AllObjects.FindGUID(a.InheritedObjectType); found {
				// 	result += fmt.Sprintf(" inherited OBJECT %v (%v)", o.OneAttr(Description), a.InheritedObjectType)
			} else {
				result += " inherited " + a.InheritedObjectType.String() + " (not found)"
			}
		} else {
			result += " inherited " + a.InheritedObjectType.String()
		}
	}

	result += fmt.Sprintf(" %08x", a.Mask)

	var rights []string
	if a.Mask&RIGHT_GENERIC_READ != 0 {
		rights = append(rights, "GENERIC_READ")
	}
	if a.Mask&RIGHT_GENERIC_WRITE != 0 {
		rights = append(rights, "GENERIC_WRITE")
	}
	if a.Mask&RIGHT_GENERIC_EXECUTE != 0 {
		rights = append(rights, "GENERIC_EXECUTE")
	}
	if a.Mask&RIGHT_GENERIC_ALL != 0 {
		rights = append(rights, "GENERIC_ALL")
	}
	if a.Mask&RIGHT_MAXIMUM_ALLOWED != 0 {
		rights = append(rights, "MAXIMUM_ALLOWED")
	}
	if a.Mask&RIGHT_ACCESS_SYSTEM_SECURITY != 0 {
		rights = append(rights, "ACCESS_SYSTEM_SECURITY")
	}
	if a.Mask&RIGHT_SYNCRONIZE != 0 {
		rights = append(rights, "SYNCRONIZE")
	}
	if a.Mask&RIGHT_WRITE_OWNER != 0 {
		rights = append(rights, "WRITE_OWNER")
	}
	if a.Mask&RIGHT_WRITE_DACL != 0 {
		rights = append(rights, "WRITE_DACL")
	}
	if a.Mask&RIGHT_READ_CONTROL != 0 {
		rights = append(rights, "READ_CONTROL")
	}
	if a.Mask&RIGHT_DELETE != 0 {
		rights = append(rights, "DELETE")
	}
	if a.Mask&RIGHT_DS_CONTROL_ACCESS != 0 {
		rights = append(rights, "DS_CONTROL_ACCESS")
	}

	if a.Mask&RIGHT_DS_LIST_OBJECT != 0 {
		rights = append(rights, "DS_LIST_OBJECT")
	}
	if a.Mask&RIGHT_DS_DELETE_TREE != 0 {
		rights = append(rights, "DS_DELETE_TREE")
	}
	if a.Mask&RIGHT_DS_WRITE_PROPERTY != 0 {
		rights = append(rights, "DS_WRITE_PROPERTY")
	}
	if a.Mask&RIGHT_DS_READ_PROPERTY != 0 {
		rights = append(rights, "DS_READ_PROPERTY")
	}
	if a.Mask&RIGHT_DS_WRITE_PROPERTY_EXTENDED != 0 {
		rights = append(rights, "DS_WRITE_PROPERTY_EXTENDED")
	}
	if a.Mask&RIGHT_DS_LIST_CONTENTS != 0 {
		rights = append(rights, "DS_LIST_CONTENTS")
	}
	if a.Mask&RIGHT_DS_DELETE_CHILD != 0 {
		rights = append(rights, "DS_DELETE_CHILD")
	}
	if a.Mask&RIGHT_DS_CREATE_CHILD != 0 {
		rights = append(rights, "DS_CREATE_CHILD")
	}
	result += " " + strings.Join(rights, " | ")
	return result
}

type SecurityDescriptor struct {
	Owner   windowssecurity.SID
	Group   windowssecurity.SID
	SACL    ACL
	DACL    ACL
	Control SecurityDescriptorControlFlag
}

func (sd *SecurityDescriptor) Equals(sd2 *SecurityDescriptor) bool {
	return reflect.DeepEqual(sd, sd2)
}

type ACL struct {
	Entries      []ACE
	Revision     byte
	containsdeny bool
}

func (a *ACL) Sort() {
	sort.Slice(a.Entries, func(i, j int) bool {
		if a.Entries[i].Flags&ACEFLAG_INHERITED_ACE == 0 && a.Entries[j].Flags&ACEFLAG_INHERITED_ACE != 0 {
			return true // NOT INHERITED should be before INHERITED
		}
		if (a.Entries[i].Type == ACETYPE_ACCESS_DENIED || a.Entries[i].Type == ACETYPE_ACCESS_DENIED_OBJECT) &&
			(a.Entries[j].Type == ACETYPE_ACCESS_ALLOWED || a.Entries[j].Type == ACETYPE_ACCESS_ALLOWED_OBJECT) {
			return true // DENIED should be before ALLOWED
		}
		return false // It's fine
	})
}

type ACE struct {
	SID                 windowssecurity.SID
	Mask                ACLPermissionMask
	Flags               uint32
	InheritedObjectType uuid.UUID
	ObjectType          uuid.UUID
	ACEFlags            byte
	Type                byte
}

func ParseSecurityDescriptor(data []byte) (SecurityDescriptor, error) {
	var result SecurityDescriptor
	if len(data) < 20 {
		return SecurityDescriptor{}, errors.New("not enough data")
	}
	if data[0] != 1 {
		return SecurityDescriptor{}, errors.New("unknown Revision")
	}
	if data[1] != 0 {
		return SecurityDescriptor{}, errors.New("unknown Sbz1")
	}
	result.Control = SecurityDescriptorControlFlag(binary.LittleEndian.Uint16(data[2:4]))
	OffsetOwner := binary.LittleEndian.Uint32(data[4:8])
	if result.Control&CONTROLFLAG_OWNER_DEFAULTED == 0 && OffsetOwner == 0 {
		log.Debug().Msgf("ACL has no owner, and does not default")
	}
	OffsetGroup := binary.LittleEndian.Uint32(data[8:12])
	if result.Control&CONTROLFLAG_GROUP_DEFAULTED == 0 && OffsetGroup == 0 {
		log.Debug().Msgf("ACL has no group, and does not default")
	}
	OffsetSACL := binary.LittleEndian.Uint32(data[12:16])
	if result.Control&CONTROLFLAG_SACL_PRESENT != 0 && OffsetSACL == 0 {
		log.Debug().Msgf("ACL has no SACL, but claims to have it")
	}
	OffsetDACL := binary.LittleEndian.Uint32(data[16:20])
	if result.Control&CONTROLFLAG_DACL_PRESENT != 0 && OffsetDACL == 0 {
		log.Debug().Msgf("ACL has no DACL, but claims to have it")
	}
	var err error
	if OffsetOwner > 0 {
		result.Owner, _, err = windowssecurity.ParseSID(data[OffsetOwner:])
		if err != nil {
			return result, err
		}
	}
	if OffsetGroup > 0 {
		result.Group, _, err = windowssecurity.ParseSID(data[OffsetGroup:])
		if err != nil {
			return result, err
		}
	}
	if OffsetSACL > 0 {
		result.SACL, err = ParseACL(data[OffsetSACL:])
		if err != nil {
			return result, err
		}
	}
	if OffsetDACL > 0 {
		result.DACL, err = ParseACL(data[OffsetDACL:])
		if result.DACL.containsdeny {
			/*			var debug bool
						lastdeny := 0
						firstallow := len(result.DACL.Entries) - 1

						for i, ace := range result.DACL.Entries {
							switch ace.Type {
							case ACETYPE_ACCESS_ALLOWED, ACETYPE_ACCESS_ALLOWED_OBJECT:
								if i < firstallow {
									firstallow = i
								}
							case ACETYPE_ACCESS_DENIED, ACETYPE_ACCESS_DENIED_OBJECT:
								if i > lastdeny {
									lastdeny = i
								}
							}
						}
						if lastdeny > firstallow {
							debug = true
						}
						if debug {
							log.Info().Msg("Before sorting:")
							log.Info().Msg(result.DACL.String(nil))
						}*/
			result.DACL.Sort()
			/*if debug {
				log.Info().Msg("After sorting:")
				log.Info().Msg(result.DACL.String(nil))
				log.Info().Msg("SORT INFO DONE")
			}*/
		}
		if err != nil {
			return result, err
		}
	}

	return result, nil
}

func (sd SecurityDescriptor) String(ao *Objects) string {
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
		result += "DACL:\n" + sd.DACL.String(ao)
	}
	if sd.Control&CONTROLFLAG_SACL_PRESENT != 0 {
		result += "DACL:\n" + sd.SACL.String(ao)
	}
	return result
}
