package windowssecurity

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unsafe"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/lkarlslund/adalanche/modules/ui"
)

var ErrorOnlySIDVersion1Supported = errors.New("only SID version 1 supported")

type SID string

// Windows representation
// 0 = revision (always 1)
// 1 = subauthority count
// 2-7 = authority
// 8-11+ = chunks of 4 with subauthorities

// Our representation
// 0-5 = authority
// 6-9+ = chunks of 4 with subauthorities

var sidDeduplicator gsync.MapOf[SID, SID]

func BytesToSID(data []byte) (SID, []byte, error) {
	if len(data) == 0 {
		return "", data, errors.New("No data supplied")
	}
	if data[0] != 0x01 {
		if len(data) > 32 {
			data = data[:32]
		}
		return "", data, fmt.Errorf("SID revision must be 1 (dump %x ...)", data)
	}
	subauthoritycount := int(data[1])
	if subauthoritycount > 15 {
		return "", data, errors.New("SID subauthority count is more than 15")
	}

	// two step lookup to avoid unnecessary allocations
	sidend := 8 + 4*subauthoritycount
	if cached, found := sidDeduplicator.Load(SID(string(data[2:sidend]))); found {
		return cached, data[sidend:], nil
	}
	// not found, create new and try again
	lookup := SID(string(data[2:sidend]))
	cached, _ := sidDeduplicator.LoadOrStore(lookup, lookup)
	return cached, data[sidend:], nil
}

func ParseStringSID(input string) (SID, error) {
	if len(input) < 5 {
		return "", errors.New("SID string is too short to be a SID")
	}
	subauthoritycount := strings.Count(input, "-") - 2
	if subauthoritycount < 0 {
		return "", errors.New("Less than one subauthority found")
	}
	if input[0] != 'S' {
		return "", errors.New("SID must start with S")
	}
	var sid = make([]byte, 6+4*subauthoritycount)

	strnums := strings.Split(input, "-")

	version, err := strconv.ParseUint(strnums[1], 10, 8)
	if err != nil {
		return "", err
	}
	if version != 1 {
		return "", ErrorOnlySIDVersion1Supported
	}

	authority, err := strconv.ParseInt(strnums[2], 10, 48)
	if err != nil {
		return "", err
	}
	authslice := make([]byte, 8)
	binary.BigEndian.PutUint64(authslice, uint64(authority)<<16) // dirty tricks
	copy(sid[0:], authslice[0:6])

	for i := range subauthoritycount {
		subauthority, err := strconv.ParseUint(strnums[3+i], 10, 32)
		if err != nil {
			return "", err
		}
		binary.LittleEndian.PutUint32(sid[6+4*i:], uint32(subauthority))
	}

	// two step lookup to avoid unnecessary allocations
	if cached, found := sidDeduplicator.Load(SID(sid)); found {
		return cached, nil
	}
	// not found, create new and try again
	lookup := SID(sid)
	cached, _ := sidDeduplicator.LoadOrStore(lookup, lookup)
	return cached, nil
}

func MustParseStringSID(input string) SID {
	sid, err := ParseStringSID(input)
	if err != nil {
		panic(err)
	}
	return sid
}

func (sid SID) IsNull() bool {
	return sid == ""
}

func (sid SID) String() string {
	if sid == "" {
		return "NULL SID"
	}
	var authority uint64
	for i := 0; i <= 5; i++ {
		authority = authority<<8 | uint64(sid[i])
	}
	s := fmt.Sprintf("S-1-%d", authority)

	// Subauthorities
	for i := 6; i < len(sid); i += 4 {
		subauthority := binary.LittleEndian.Uint32([]byte(sid[i:]))
		s += fmt.Sprintf("-%d", subauthority)
	}
	return s
}

func (sid SID) MarshalJSON() ([]byte, error) {
	return json.Marshal(sid.String())
}

func (sid *SID) UnmarshalJSON(data []byte) error {
	var sidstring string
	err := json.Unmarshal(data, &sidstring)
	if err != nil {
		return err
	}
	newsid, err := ParseStringSID(sidstring)
	*sid = newsid
	return err
}

func (sid SID) Components() int {
	return (len(sid) + 2) / 4
}

func (sid SID) Component(n int) uint64 {
	switch n {
	case 0:
		if len(sid) == 0 {
			return 0 // FAIL
		}
		return 1 // always version 1
	case 1:
		if len(sid) < 8 {
			return 0 // FAIL
		}

		var authority uint64
		for i := 0; i <= 5; i++ {
			authority = authority<<8 | uint64(sid[i])
		}
		return authority
	default:
		offset := n*4 - 2
		if len(sid) < offset+3 {
			return 0 // FAIL
		}
		return uint64(binary.LittleEndian.Uint32([]byte(sid[offset:])))
	}
}

func (sid SID) StripRID() SID {
	if len(sid) < 10 {
		ui.Error().Msgf("SID %s is too short to strip RID", sid)
		return ""
	}
	return sid[:len(sid)-4]
}

func (sid SID) RID() uint32 {
	if len(sid) <= 6 {
		return 0
	}
	l := len(sid) - 4
	return binary.LittleEndian.Uint32([]byte(sid[l:]))
}

func (sid SID) IsBlank() bool {
	return sid == ""
}

func (sid SID) AddComponent(component uint32) SID {
	newsid := make([]byte, len(sid)+4)
	copy(newsid, sid)
	binary.LittleEndian.PutUint32(newsid[len(sid):], component)
	newsid[1] = byte(len(newsid)/4) - 2 // Adjust internal length
	return SID(newsid)
}

func SIDFromPtr(data uintptr) (SID, error) {
	bytes := (*[1024]byte)(unsafe.Pointer(data))
	if bytes[0] != 0x01 {
		return "", fmt.Errorf("SID revision must be 1 (dump %x ...)", bytes[0:32])
	}
	subauthoritycount := int(bytes[1])
	var sid = make([]byte, 6+4*subauthoritycount)

	copy(sid, bytes[2:len(sid)])
	return SID(sid), nil
}

// Calculate a Windows service SID by converting servicename to uppercase, converting to Unicode 16, running through SHA1, and then converting to SID
func ServiceNameToServiceSID(servicename string) SID {
	use := utf16.Encode([]rune(strings.ToUpper(servicename)))
	rawbytes := (*[16384]byte)(unsafe.Pointer(&use[0]))[:len(use)*2]
	huse := sha1.Sum(rawbytes)
	var sidbytes [30]byte
	sidbytes[5] = 5
	sidbytes[6] = 80
	copy(sidbytes[10:], huse[:])
	return SID(sidbytes[:])
}
