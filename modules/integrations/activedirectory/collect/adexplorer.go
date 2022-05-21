package collect

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/binstruct"
)

type ADEXAttributeType uint32

const (
	ADSTYPE_INVALID ADEXAttributeType = iota
	ADSTYPE_DN_STRING
	ADSTYPE_CASE_EXACT_STRING
	ADSTYPE_CASE_IGNORE_STRING
	ADSTYPE_PRINTABLE_STRING
	ADSTYPE_NUMERIC_STRING
	ADSTYPE_BOOLEAN
	ADSTYPE_INTEGER
	ADSTYPE_OCTET_STRING
	ADSTYPE_UTC_TIME
	ADSTYPE_LARGE_INTEGER
	ADSTYPE_PROV_SPECIFIC
	ADSTYPE_OBJECT_CLASS
	ADSTYPE_CASEIGNORE_LIST
	ADSTYPE_OCTET_LIST
	ADSTYPE_PATH
	ADSTYPE_POSTALADDRESS
	ADSTYPE_TIMESTAMP
	ADSTYPE_BACKLINK
	ADSTYPE_TYPEDNAME
	ADSTYPE_HOLD
	ADSTYPE_NETADDRESS
	ADSTYPE_REPLICAPOINTER
	ADSTYPE_FAXNUMBER
	ADSTYPE_EMAIL
	ADSTYPE_NT_SECURITY_DESCRIPTOR
	ADSTYPE_UNKNOWN
	ADSTYPE_DN_WITH_BINARY
	ADSTYPE_DN_WITH_STRING
)

type ADEXHeader struct {
	Signature Cstring
	Version   uint32

	FileTime    uint64
	Description Wstring `bin:"len:260"`
	Server      Wstring `bin:"len:260"`

	ObjectCount    uint32
	AttributeCount uint32

	OffsetPRC uint64
	OffsetEnd uint64

	Properties ADEXProperties `bin:"offsetStart:OffsetPRC"`
	Classes    ADEXClasses
	Rights     ADEXRights

	Objects []ADEXObject `bin:"len:ObjectCount,offsetStart:1086"`
}

type ADEXObject struct {
	Position CurrentPosition
	Size     uint32
	Count    uint32
	Entries  []ADEXEntry `bin:"len:Count"`
	Blob     struct{}    `bin:"SkipData"`
}

func (o *ADEXObject) SkipData(r binstruct.Reader) error {
	skip := int64(o.Size - 8 - o.Count*8)
	if skip < 0 {
		return fmt.Errorf("invalid object size %v", o.Size)
	}
	_, err := r.Seek(skip, os.SEEK_CUR)
	return err
}

func (o *ADEXObject) GetValues(r *binstruct.Decoder, attr []ADEXProperty, offsetcache map[int64][]string) (map[string][]string, error) {
	results := make(map[string][]string)
	for _, e := range o.Entries {
		a := attr[e.Attribute]

		if cachedvalues, found := offsetcache[int64(o.Position)+int64(e.Offset)]; found {
			results[string(a.Name)] = cachedvalues
			continue
		}

		ad := AttributeDecoder{
			attributeType: ADEXAttributeType(a.Encoding),
			position:      int64(o.Position) + int64(e.Offset),
		}
		err := r.Decode(&ad)
		if err != nil {
			return nil, err
		}

		// Save to the cache
		offsetcache[int64(o.Position)+int64(e.Offset)] = ad.results

		// Add to the result
		results[string(a.Name)] = ad.results
	}
	return results, nil
}

type AttributeDecoder struct {
	attributeType ADEXAttributeType
	position      int64
	size          uint32
	results       []string
}

func (ad *AttributeDecoder) BinaryDecode(r binstruct.Reader) error {
	r.Seek(int64(ad.position), os.SEEK_SET)

	count, err := r.ReadUint32()
	if err != nil {
		return err
	}

	ad.results = make([]string, count, count)

	var localoffsets []uint32

	for i := 0; i < int(count); i++ {
		var value string

		switch ad.attributeType {
		case ADSTYPE_INVALID:
			return fmt.Errorf("invalid attribute type")
		case ADSTYPE_DN_STRING,
			ADSTYPE_CASE_EXACT_STRING,
			ADSTYPE_CASE_IGNORE_STRING,
			ADSTYPE_PRINTABLE_STRING,
			ADSTYPE_NUMERIC_STRING,
			ADSTYPE_OBJECT_CLASS:

			// First read the offsets
			if i == 0 {
				localoffsets = make([]uint32, count, count)
				for i := range localoffsets {
					localoffsets[i], err = r.ReadUint32()
					if err != nil {
						return err
					}
				}
			}

			thispos := ad.position + int64(localoffsets[i])

			r.Seek(thispos, os.SEEK_SET)

			var wc WCstring
			err = r.Unmarshal(&wc)
			if err != nil {
				return err
			}
			value = string(wc)
		case ADSTYPE_OCTET_STRING, ADSTYPE_NT_SECURITY_DESCRIPTOR:
			// First read the lengths (store in localoffsets)
			if i == 0 {
				localoffsets = make([]uint32, count, count)
				for i := range localoffsets {
					localoffsets[i], err = r.ReadUint32()
					if err != nil {
						return err
					}
				}
			}

			_, s, err := r.ReadBytes(int(localoffsets[i]))
			if err != nil {
				return err
			}

			value = string(s)
		case ADSTYPE_BOOLEAN:
			b, err := r.ReadUint32()
			if err != nil {
				return err
			}
			if b == 0 {
				value = "0"
			} else {
				value = "1"
			}
		case ADSTYPE_INTEGER:
			v, err := r.ReadUint32()
			if err != nil {
				return err
			}
			value = strconv.FormatInt(int64(v), 10)
		case ADSTYPE_UTC_TIME:
			var t SystemTime
			err := r.Unmarshal(&t)
			if err != nil {
				return err
			}
			value = t.Time().Format("20060102150405.0Z")
		case ADSTYPE_LARGE_INTEGER:
			v, err := r.ReadInt64()
			if err != nil {
				return err
			}
			value = strconv.FormatInt(v, 10)
		default:
			return fmt.Errorf("unhandled attribute type %v", ad.attributeType)
		}

		if value != "" {
			ad.results[i] = value
		} else {
			return fmt.Errorf("no results for attribute type %v", ad.attributeType)
		}
	}

	return nil
}

type ADEXEntry struct {
	Attribute uint32
	Offset    int32
}

type ADEXProperty struct {
	Name                  WStringLength
	Unknown               uint32
	Encoding              uint32
	DN                    WStringLength
	SchemaIDGUID          uuid.UUID
	AttributeSecurityGUID uuid.UUID
	Blob                  uint32
}

type ADEXProperties struct {
	Count uint32
	Props []ADEXProperty `bin:"len:Count"`
}

type ADEXBlock struct {
	Unknown1 uint32
	Unknown2 WStringLength
}

type ADEXClass struct {
	ClassName       WStringLength
	DN              WStringLength
	CommonClassName WStringLength
	SubClassOf      WStringLength
	SchemaIDGUID    uuid.UUID

	OffsetToNumBlocks uint32
	OffsetData        []byte `bin:"len:OffsetToNumBlocks"`

	NumBlocks uint32
	Blocks    []ADEXBlock `bin:"len:NumBlocks"`

	ExtraShizLength uint32
	ExtraShiz       []byte `bin:"len:ExtraShizLength*16"`

	NumPossSuperiors uint32
	PossSuperiors    []WStringLength `bin:"len:NumPossSuperiors"`

	NumAuxiliaryClasses uint32
	AuxiliaryClasses    []WStringLength `bin:"len:NumAuxiliaryClasses"`
}

type ADEXClasses struct {
	Count   uint32
	Classes []ADEXClass `bin:"len:Count"`
}

type ADEXRight struct {
	Name        WStringLength
	Description WStringLength
	Blob        [20]byte
}

type ADEXRights struct {
	Count  uint32
	Rights []ADEXRight `bin:"len:Count"`
}

type SystemTime struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

func (st *SystemTime) Time() time.Time {
	return time.Date(int(st.Year), time.Month(st.Month), int(st.Day), int(st.Hour), int(st.Minute), int(st.Second), int(st.Milliseconds), time.UTC)
}

type CurrentPosition int64

func (cp *CurrentPosition) BinaryDecode(r binstruct.Reader) error {
	pos, err := r.Seek(0, os.SEEK_CUR)
	if err != nil {
		return err
	}
	*cp = CurrentPosition(uint64(pos))
	return nil
}

type WStringLength string

func (wsl *WStringLength) BinaryDecode(r binstruct.Reader) error {
	length, err := r.ReadUint32()
	if err != nil {
		return err
	}

	if length == 0 {
		return nil
	}

	data := make([]uint16, int(length)/2, int(length)/2)

	for i := range data {
		data[i], err = r.ReadUint16()
		if err != nil {
			return err
		}
	}

	if data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}

	result := WStringLength(string(utf16.Decode(data)))
	*wsl = result

	return nil
}

type Wstring []uint16

func (w Wstring) String() string {
	return strings.TrimRight(string(utf16.Decode(w)), "\x00")
}

type WCstring string

func (wc *WCstring) BinaryDecode(r binstruct.Reader) error {
	buffer := make([]uint16, 0, 64)

	for {
		c, err := r.ReadUint16()
		if err != nil {
			return err
		}

		if c == 0 {
			break
		}

		buffer = append(buffer, c)
	}

	runes := utf16.Decode(buffer)
	*wc = WCstring(string(runes))
	return nil
}

type Cstring string

func (c *Cstring) BinaryDecode(r binstruct.Reader) error {
	buffer := make([]byte, 0, 64)

	for {
		c, err := r.ReadByte()
		if err != nil {
			return err
		}

		if c == 0 {
			break
		}

		buffer = append(buffer, c)
	}

	*c = Cstring(string(buffer))
	return nil
}

type AttributeValueData struct {
	Count        uint32
	LocalOffsets []uint32 `bin:"len:Count"`
}

func DumpFromADExplorer(path string) ([]activedirectory.RawObject, error) {
	raw, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Header

	dec := binstruct.NewDecoder(raw, binary.LittleEndian)

	var header ADEXHeader
	err = dec.Decode(&header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	if header.Signature != "win-ad-ob" {
		return nil, fmt.Errorf("Invalid AD Explorer data file signature: %v", header.Signature)
	}

	if header.Version != 0x00010001 {
		return nil, fmt.Errorf("Invalid AD Explorer data file marker: %v", header.Version)
	}

	ao := make([]activedirectory.RawObject, header.ObjectCount)

	offsetcache := make(map[int64][]string)

	for i, ado := range header.Objects {
		var ro activedirectory.RawObject
		ro.Attributes = make(map[string][]string)

		values, err := ado.GetValues(dec, header.Properties.Props, offsetcache)
		if err != nil {
			return nil, fmt.Errorf("failed to get values for object %d: %v", i, err)
		}

		ro.Attributes = values
		ro.DistinguishedName = ro.Attributes["distinguishedName"][0]

		ao[i] = ro
	}

	return ao, nil
}
