package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lkarlslund/stringdedup"
)

type SID string

// 0 = revision
// 1-6 = authority
// 7-10+ = chunks of 4 with subauthorities

func ParseSID(data []byte) (SID, []byte, error) {
	if len(data) == 0 {
		return SID(""), data, errors.New("No data supplied")
	}
	if data[0] != 0x01 {
		return "", data, fmt.Errorf("SID revision must be 1 (dump %x)", data)
	}
	subauthoritycount := int(data[1])
	var sid = make([]byte, 8+4*subauthoritycount)
	if subauthoritycount > 15 {
		return "", data, errors.New("SID subauthority count is more than 15")
	}
	copy(sid, data[0:len(sid)])
	return SID(stringdedup.S(string(sid))), data[8+subauthoritycount*4:], nil
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

	version, err := strconv.ParseInt(strnums[1], 10, 8)
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
		subauthority, err := strconv.ParseInt(strnums[3+i], 10, 32)
		if err != nil {
			return "", err
		}
		binary.LittleEndian.PutUint32(sid[8+4*i:], uint32(subauthority))
	}
	return SID(stringdedup.S(string(sid))), nil
}

func (sid SID) IsNull() bool {
	return sid == ""
}

func (sid SID) ToString() string {
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

func (sid SID) String() string {
	s := sid.ToString()

	if o, found := AllObjects.FindSID(sid); found {
		s += " (" + o.DN() + ")"
	}

	return s
}

func (sid SID) RID() uint32 {
	if len(sid) <= 8 {
		return 0
	}
	l := len(sid) - 4
	return binary.LittleEndian.Uint32([]byte(sid[l:]))
}
