package engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// ParseSDDL reads an ordinary discretionary ACL. Unsupported ACEs and identities
// return an error rather than an empty (apparently successfully parsed) ACL.
func ParseSDDL(value string) (ACL, error) {
	start := strings.Index(value, "D:")
	if start < 0 {
		return ACL{}, fmt.Errorf("SDDL has no DACL")
	}
	body := value[start+2:]
	if end := strings.Index(body, "S:"); end >= 0 {
		body = body[:end]
	}
	if strings.HasPrefix(body, "NO_ACCESS_CONTROL") {
		return ACL{}, fmt.Errorf("SDDL has a null DACL")
	}
	acl := ACL{Revision: 2}
	flags, entries, hasEntries := strings.Cut(body, "(")
	for flags != "" {
		switch {
		case strings.HasPrefix(flags, "AI"), strings.HasPrefix(flags, "AR"):
			flags = flags[2:]
		case strings.HasPrefix(flags, "P"):
			flags = flags[1:]
		default:
			return ACL{}, fmt.Errorf("unsupported DACL flags")
		}
	}
	if !hasEntries {
		return acl, nil
	}
	entries = "(" + entries
	for entries != "" {
		if entries[0] != '(' {
			return ACL{}, fmt.Errorf("invalid SDDL ACE boundary")
		}
		end := strings.IndexByte(entries, ')')
		if end < 0 {
			return ACL{}, fmt.Errorf("unterminated SDDL ACE")
		}
		fields := strings.Split(entries[1:end], ";")
		entries = entries[end+1:]
		if len(fields) != 6 || fields[3] != "" || fields[4] != "" {
			return ACL{}, fmt.Errorf("unsupported conditional or object-specific SDDL ACE")
		}
		var ace ACE
		switch fields[0] {
		case "A":
			ace.Type = ACETYPE_ACCESS_ALLOWED
		case "D":
			ace.Type = ACETYPE_ACCESS_DENIED
		default:
			return ACL{}, fmt.Errorf("unsupported SDDL ACE type")
		}
		for f := fields[1]; f != ""; {
			if len(f) < 2 {
				return ACL{}, fmt.Errorf("invalid SDDL ACE flags")
			}
			flag, ok := map[string]ACEFlags{"OI": ACEFLAG_OBJECT_INHERIT_ACE, "CI": ACEFLAG_INHERIT_ACE, "NP": ACEFLAG_NO_PROPAGATE_INHERIT_ACE, "IO": ACEFLAG_INHERIT_ONLY_ACE, "ID": ACEFLAG_INHERITED_ACE}[f[:2]]
			if !ok {
				return ACL{}, fmt.Errorf("unsupported SDDL ACE flags")
			}
			ace.ACEFlags |= flag
			f = f[2:]
		}
		if strings.HasPrefix(fields[2], "0x") {
			mask, err := strconv.ParseUint(fields[2][2:], 16, 32)
			if err != nil {
				return ACL{}, fmt.Errorf("invalid SDDL mask: %w", err)
			}
			ace.Mask = Mask(mask)
		} else {
			for rights := fields[2]; rights != ""; {
				if len(rights) < 2 {
					return ACL{}, fmt.Errorf("invalid SDDL rights")
				}
				mask, ok := sddlRights[rights[:2]]
				if !ok {
					return ACL{}, fmt.Errorf("unsupported SDDL right")
				}
				ace.Mask |= mask
				rights = rights[2:]
			}
		}
		identity := fields[5]
		if sid, ok := sddlIdentities[identity]; ok {
			identity = sid
		}
		var err error
		ace.SID, err = windowssecurity.ParseStringSID(identity)
		if err != nil {
			return ACL{}, fmt.Errorf("unsupported or invalid SDDL identity")
		}
		acl.Entries = append(acl.Entries, ace)
		if ace.Type == ACETYPE_ACCESS_DENIED {
			acl.containsdeny = true
		}
	}
	return acl, nil
}

var sddlRights = map[string]Mask{"GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000, "RC": 0x20000, "SD": 0x10000, "WD": 0x40000, "WO": 0x80000, "CC": 1, "DC": 2, "LC": 4, "SW": 8, "RP": 16, "WP": 32, "DT": 64, "LO": 128, "CR": 256, "FA": 0x1f01ff, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200a0, "KA": 0xf003f, "KR": 0x20019, "KW": 0x20006, "KX": 0x20019}
var sddlIdentities = map[string]string{"SY": "S-1-5-18", "BA": "S-1-5-32-544", "BU": "S-1-5-32-545", "BG": "S-1-5-32-546", "AU": "S-1-5-11", "WD": "S-1-1-0", "LS": "S-1-5-19", "NS": "S-1-5-20", "IU": "S-1-5-4", "NU": "S-1-5-2", "SU": "S-1-5-6", "AN": "S-1-5-7", "CO": "S-1-3-0", "CG": "S-1-3-1", "OW": "S-1-3-4", "RC": "S-1-5-12", "AC": "S-1-15-2-1", "RD": "S-1-5-32-555"}
