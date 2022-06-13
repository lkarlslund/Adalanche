package windowssecurity

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/lkarlslund/adalanche/modules/dedup"
	"github.com/rs/zerolog/log"
)

type SID string

const BlankSID = SID("")

// 0 = revision
// 1 = subauthority count
// 2-7 = authority
// 8-11+ = chunks of 4 with subauthorities

func ParseSID(data []byte) (SID, []byte, error) {
	if len(data) == 0 {
		return SID(""), data, errors.New("No data supplied")
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
	length := 8 + 4*subauthoritycount
	return SID(dedup.D.BS(data[0:length])), data[length:], nil
}

func SIDFromString(input string) (SID, error) {
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
	var sid = make([]byte, 8+4*subauthoritycount)

	strnums := strings.Split(input, "-")

	version, err := strconv.ParseUint(strnums[1], 10, 8)
	if err != nil {
		return "", err
	}
	sid[0] = byte(version)
	sid[1] = byte(subauthoritycount)

	authority, err := strconv.ParseInt(strnums[2], 10, 48)
	if err != nil {
		return "", err
	}
	authslice := make([]byte, 8)
	binary.BigEndian.PutUint64(authslice, uint64(authority)<<16) // dirty tricks
	copy(sid[2:], authslice[0:6])

	for i := 0; i < subauthoritycount; i++ {
		subauthority, err := strconv.ParseUint(strnums[3+i], 10, 32)
		if err != nil {
			return "", err
		}
		binary.LittleEndian.PutUint32(sid[8+4*i:], uint32(subauthority))
	}
	return SID(dedup.D.S(string(sid))), nil
}

func (sid SID) IsNull() bool {
	return sid == ""
}

func (sid SID) String() string {
	if sid == "" {
		return "NULL SID"
	}
	var authority uint64
	for i := 2; i <= 7; i++ {
		authority = authority<<8 | uint64(sid[i])
	}
	s := fmt.Sprintf("S-%d-%d", sid[0], authority)

	// Subauthorities
	for i := 8; i < len(sid); i += 4 {
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
	newsid, err := SIDFromString(sidstring)
	*sid = newsid
	return err
}

func (sid SID) Components() int {
	return len(sid) / 4
}

func (sid SID) Component(n int) uint64 {
	switch n {
	case 0:
		if len(sid) == 0 {
			return 0 // FAIL
		}
		return uint64(sid[0])
	case 1:
		if len(sid) < 8 {
			return 0 // FAIL
		}

		var authority uint64
		for i := 2; i <= 7; i++ {
			authority = authority<<8 | uint64(sid[i])
		}
		return authority
	default:
		offset := n * 4
		if len(sid) < offset+3 {
			return 0 // FAIL
		}
		return uint64(binary.LittleEndian.Uint32([]byte(sid[offset:])))
	}
}

func (sid SID) StripRID() SID {
	if len(sid) < 12 {
		log.Error().Msgf("SID %s is too short to strip RID", sid)
		return ""
	}
	newsid := make([]byte, len(sid)-4)
	copy(newsid, sid)
	newsid[1] = byte(len(newsid)/4) - 2 // Adjust internal length
	return SID(newsid)
}

func (sid SID) RID() uint32 {
	if len(sid) <= 8 {
		return 0
	}
	l := len(sid) - 4
	return binary.LittleEndian.Uint32([]byte(sid[l:]))
}

func (sid SID) AddComponent(component uint32) SID {
	newsid := make([]byte, len(sid)+4)
	copy(newsid, sid)
	binary.LittleEndian.PutUint32(newsid[len(sid):], component)
	newsid[1] = byte(len(newsid)/4) - 2 // Adjust internal length
	return SID(newsid)
}

func SIDFromBytes(data uintptr) (SID, error) {
	bytes := (*[1024]byte)(unsafe.Pointer(data))
	if bytes[0] != 0x01 {
		return "", fmt.Errorf("SID revision must be 1 (dump %x ...)", bytes[0:32])
	}
	subauthoritycount := int(bytes[1])
	var sid = make([]byte, 8+4*subauthoritycount)

	copy(sid, bytes[0:len(sid)])
	return SID(sid), nil
}
