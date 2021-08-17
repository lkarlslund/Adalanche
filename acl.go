package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

type SecurityDescriptorControlFlag uint16

// http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm

const (
	CONTROLFLAG_OWNER_DEFAULTED     SecurityDescriptorControlFlag = 0x0001
	CONTROLFLAG_GROUP_DEFAULTED                                   = 0x0002
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

	RIGHT_GENERIC_READ = RIGHT_READ_CONTROL | RIGHT_DS_LIST_CONTENTS | RIGHT_DS_READ_PROPERTY | RIGHT_DS_LIST_OBJECT /*
		** Mask value is not stored in AD but deduced from mask bits combined **
		RIGHT_GENERIC_READ = 0x80000000 /*
			The right to read permissions and all properties of the object, and list the contents of the
			object in the case of containers.

			Equivalent to:RIGHT_READ_CONTROL | RIGHT_DS_LIST_CONTENTS | RIGHT_DS_READ_PROPERTY | RIGHT_DS_LIST_OBJECT */

	RIGHT_GENERIC_WRITE = RIGHT_READ_CONTROL | RIGHT_DS_WRITE_PROPERTY | RIGHT_DS_WRITE_PROPERTY_EXTENDED /*
		** Mask value is not stored in AD but deduced from mask bits combined **
		RIGHT_GENERIC_WRITE = 0x40000000 /*
			Includes the right to read permissions on the object, and the right to write all the properties
			on the object.

			Equivalent to: RIGHT_READ_CONTROL | RIGHT_DS_WRITE_PROPERTY | RIGHT_DS_WRITE_PROPERTY_EXTENDED */

	RIGHT_GENERIC_EXECUTE = RIGHT_READ_CONTROL | RIGHT_DS_LIST_CONTENTS /*
		** Mask value is not stored in AD but deduced from mask bits combined **
		RIGHT_GENERIC_EXECUTE = 0x20000000 /*
			The right to read permissions/list the contents of a container object.

			Equivalent to: RIGHT_READ_CONTROL | RIGHT_DS_LIST_CONTENTS */
	RIGHT_GENERIC_ALL = RIGHT_DELETE | RIGHT_READ_CONTROL | RIGHT_WRITE_DACL | RIGHT_WRITE_OWNER | RIGHT_DS_CREATE_CHILD | RIGHT_DS_DELETE_CHILD | RIGHT_DS_DELETE_TREE | RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY | RIGHT_DS_LIST_CONTENTS | RIGHT_DS_LIST_OBJECT | RIGHT_DS_CONTROL_ACCESS | RIGHT_DS_WRITE_PROPERTY_EXTENDED /*
		** Mask value is not stored in AD but deduced from mask bits combined **
		RIGHT_GENERIC_ALL = 0x10000000 /*
			The right to create/delete child objects, read/write all properties, see any child objects, add and remove the object,
			and read/write with an extended right.

			Equivalent to: RIGHT_DELETE |  RIGHT_READ_CONTROL | RIGHT_WRITE_DACL | RIGHT_WRITE_OWNER | RIGHT_DS_CREATE_CHILD | RIGHT_DS_DELETE_CHILD | RIGHT_DS_DELETE_TREE | RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY | RIGHT_DS_LIST_CONTENTS | RIGHT_DS_LIST_OBJECT | RIGHT_DS_CONTROL_ACCESS | RIGHT_DS_WRITE_PROPERTY_EXTENDED)
	*/

	RIGHT_MAXIMUM_ALLOWED = 0x02000000 /* Not stored in AD, just for requests */

	RIGHT_ACCESS_SYSTEM_SECURITY = 0x01000000 /* Not stored in AD, just for requests */

	RIGHT_SYNCRONIZE  = 0x00100000
	RIGHT_WRITE_OWNER = 0x00080000 /*
		The right to modify the owner section of the security descriptor. Of note, a user with this right can only change the owner to themselves
		-ownership cannot be transferred to other userswith only this right.*/
	RIGHT_WRITE_DACL = 0x00040000 /*
		The right to modify the DACL for the object. */
	RIGHT_READ_CONTROL = 0x00020000 /*
		The right to read alldata from the security descriptor except the SACL. */
	RIGHT_DELETE = 0x00010000 /*
		The right to delete the object. */

	RIGHT_DS_VOODOO_BIT = 0x00001000 /* No clue - see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/4be42fa6-c421-4763-890b-07a9ab5a319d for second option */

	RIGHT_DS_CONTROL_ACCESS = 0x00000100 /*
		A specific control access right (if the ObjectType GUID refers to an extended right registered in the forest schema)
		or the right to read a confidential property (if the ObjectType GUID refers to a confidential property).
		If the GUID is not present, then all extended rights are granted */
	RIGHT_DS_LIST_OBJECT = 0x00000080 /*
		The right to list an object. If the user does not have this right and also doesn’t have the
		RIGHT_DS_LIST_CONTENTS right on the object's parent container then the object is hidden from the user. */
	RIGHT_DS_DELETE_TREE = 0x00000040 /*
		The right to perform a delete-tree operation. */
	RIGHT_DS_WRITE_PROPERTY = 0x00000020 /*
		The right to write one or more properties of the object specified by the ObjectType GUID.
		If the ObjectType GUID is not present or is all 0s, then the right to write all properties is granted. */
	RIGHT_DS_READ_PROPERTY = 0x00000010 /*
		The right to read one or more properties of the object specified by the ObjectType GUID.
		If the ObjectType GUID is not present or is all 0s, then the right to read all properties is granted.	*/
	RIGHT_DS_WRITE_PROPERTY_EXTENDED = 0x00000008 /*
		The right to execute a validated write access right. AKA DsSelf */
	RIGHT_DS_LIST_CONTENTS = 0x00000004 /*
		The right to list all child objects of the object, if the object is a type of container. */
	RIGHT_DS_DELETE_CHILD = 0x00000002 /*
		The right to delete child objects of the object, if the object is a type of container.
		If the ObjectType contains a GUID, the GUID will reference the type of child object that can be deleted. */
	RIGHT_DS_CREATE_CHILD = 0x00000001 /*
		The right to create child objects under the object, if the object is a type of container.
		If the ObjectType contains a GUID, the GUID will reference the type of child object that can be created. */
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

func parseACL(data []byte) (ACL, error) {
	var acl ACL
	acl.Revision = data[0]
	// log.Debug().Msgf("Parsing ACL with revision %v", acl.Revision)
	if data[1] != 0 {
		return acl, errors.New("Bad Sbz1")
	}
	aclsize := int(binary.LittleEndian.Uint16(data[2:4]))
	if aclsize > len(data) {
		return acl, errors.New("ACL size exceeds available data")
	}
	aclcount := int(binary.LittleEndian.Uint16(data[4:6]))
	if data[6] != 0 {
		return acl, errors.New("Bad Sbz2")
	}

	acledata := data[8:]
	for i := 0; i < aclcount; i++ {
		var err error
		var ace ACE
		ace, acledata, err = parseACLentry(acledata)
		if err != nil {
			return acl, err
		}
		acl.Entries = append(acl.Entries, ace)
	}

	return acl, nil
}

func (a ACL) String() string {
	var result string
	for _, acl := range a.Entries {
		result += "ACL: " + acl.String() + "\n"
	}
	return result
}

func parseACLentry(data []byte) (ACE, []byte, error) {
	var ace ACE
	var err error
	// ACEHEADER
	ace.Type = data[0]
	ace.ACEFlags = data[1]
	// acesize := binary.LittleEndian.Uint16(data[2:])
	ace.Mask = binary.LittleEndian.Uint32(data[4:])

	data = data[8:]
	if ace.Type == ACETYPE_ACCESS_ALLOWED_OBJECT || ace.Type == ACETYPE_ACCESS_DENIED_OBJECT {
		ace.Flags = binary.LittleEndian.Uint32(data[0:])
		data = data[4:]
		if ace.Flags&OBJECT_TYPE_PRESENT != 0 {
			ace.ObjectType, err = uuid.FromBytes(data[0:16])
			if err != nil {
				return ace, data, err
			}
			ace.ObjectType = SwapUUIDEndianess(ace.ObjectType)
			data = data[16:]
		}
		if ace.Flags&INHERITED_OBJECT_TYPE_PRESENT != 0 {
			ace.InheritedObjectType, err = uuid.FromBytes(data[0:16])
			if err != nil {
				return ace, data, err
			}
			ace.InheritedObjectType = SwapUUIDEndianess(ace.InheritedObjectType)
			data = data[16:]
		}
	}

	ace.SID, data, err = ParseSID(data)
	if err != nil {
		return ace, data, err
	}
	return ace, data, nil
}

func (a ACL) AllowObjectClass(index int, o *Object, mask uint32, g uuid.UUID) bool {
	if a.Entries[index].checkObjectClass(true, o, mask, g) {
		// See if a prior one denies it
		for i := 0; i < index; i++ {
			if a.Entries[i].checkObjectClass(false, o, mask, g) && a.Entries[index].SID == a.Entries[i].SID {
				if g == NullGUID && a.Entries[i].ObjectType != NullGUID {
					// We tested for all properties / extended rights, but the DENY blocks some of these
					log.Debug().Msgf("ACL allow/deny detection: %v denies that %v allows", a.Entries[i].String(), a.Entries[index].String())
					return false
				}
				if a.Entries[i].ObjectType != NullGUID && a.Entries[i].ObjectType == g {
					// The DENY is specific to attributes / extended rights etc. so it only blocks if the requested is the same
					log.Debug().Msgf("ACL allow/deny detection: %v denies that %v allows", a.Entries[i].String(), a.Entries[index].String())
					return false
				}
			}
		}
		return true // No deny match
	}
	return false // No allow match
}

// Is the ACE something that allows or denies this type of GUID?
func (a ACE) checkObjectClass(allow bool, o *Object, mask uint32, g uuid.UUID) bool {
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
			if s, found := AllSchemaAttributes[g]; found {
				asg := s.OneAttr(AttributeSecurityGUID)
				if asg != "" {
					u, err := uuid.FromBytes([]byte(asg))
					if err != nil {
						log.Warn().Msgf("Problem converting GUID %v", err)
					} else {
						u = SwapUUIDEndianess(u)
						if a.ObjectType == u {
							typematch = true
						}
					}
				}
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

		for _, class := range o.ObjectClassGUIDs() {
			if a.InheritedObjectType == class {
				return true
			}
		}
	}

	return false
}

func (a ACE) String() string {
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
		if o, found := AllRights[a.ObjectType]; found {
			result += fmt.Sprintf(" RIGHT %v (%v)", o.OneAttr(Name), a.ObjectType)
		} else if o, found := AllSchemaClasses[a.ObjectType]; found {
			result += fmt.Sprintf(" CLASS %v (%v)", o.OneAttr(Name), a.ObjectType)
		} else if o, found := AllSchemaAttributes[a.ObjectType]; found {
			result += fmt.Sprintf(" ATTRIBUTE %v (%v)", o.OneAttr(Name), a.ObjectType)
		} else if o, found := AllObjects.FindGUID(a.ObjectType); found {
			result += fmt.Sprintf(" OBJECT? %v (%v)", o.OneAttr(Description), a.ObjectType)
		} else {
			result += " " + a.ObjectType.String() + " (not found)"
		}
	}
	if a.Flags&INHERITED_OBJECT_TYPE_PRESENT != 0 {
		// log.Debug().Msgf("Looking for right %v", a.InheritedObjectType)
		// if o, found := AllRights[a.InheritedObjectType]; found {
		// 	result += fmt.Sprintf(" inherited RIGHT %v (%v)", o.OneAttr(Name), a.InheritedObjectType)
		// } else
		if o, found := AllSchemaClasses[a.InheritedObjectType]; found {
			result += fmt.Sprintf(" inherited CLASS %v (%v)", o.OneAttr(Name), a.InheritedObjectType)
			// }
			//  else if o, found := AllSchemaAttributes[a.InheritedObjectType]; found {
			// 	result += fmt.Sprintf(" inherited ATTRIBUTE %v (%v)", o.OneAttr(Name), a.InheritedObjectType)
			// } else if o, found := AllObjects.FindGUID(a.InheritedObjectType); found {
			// 	result += fmt.Sprintf(" inherited OBJECT %v (%v)", o.OneAttr(Description), a.InheritedObjectType)
		} else {
			result += " inherited " + a.InheritedObjectType.String() + " (not found)"
		}
	}
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
