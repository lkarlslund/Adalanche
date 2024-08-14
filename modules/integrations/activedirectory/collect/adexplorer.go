package collect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/binstruct"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
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
	_, err := r.Seek(skip, io.SeekCurrent)
	return err
}

func (o *ADEXObject) GetValues(r binstruct.Reader, attr []ADEXProperty, offsetcache map[int64][]string) (map[string][]string, error) {
	results := make(map[string][]string)
	for _, e := range o.Entries {
		a := attr[e.Attribute]

		abspos := int64(o.Position) + int64(e.Offset)
		if cachedvalues, found := offsetcache[abspos]; found {
			results[string(a.Name)] = cachedvalues
			continue
		}

		ad := AttributeDecoder{
			attributeType: ADEXAttributeType(a.Encoding),
			position:      abspos,
		}
		err := r.Unmarshal(&ad)
		if err != nil {
			return nil, err
		}

		// Save to the cache
		offsetcache[abspos] = ad.results

		// Add to the result
		results[string(a.Name)] = ad.results
	}
	return results, nil
}

type AttributeDecoder struct {
	attributeType ADEXAttributeType
	position      int64
	// size          uint32
	results []string
}

func (ad *AttributeDecoder) BinaryDecode(r binstruct.Reader) error {
	_, err := r.Seek(int64(ad.position), io.SeekStart)
	if err != nil {
		return err
	}

	count, err := r.ReadUint32()
	if err != nil {
		return err
	}

	ad.results = make([]string, count)

	var localoffsets []int32

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
			ADSTYPE_OBJECT_CLASS,
			ADSTYPE_PATH,
			ADSTYPE_POSTALADDRESS,
			ADSTYPE_DN_WITH_STRING:

			// First read the offsets
			if i == 0 {
				localoffsets = make([]int32, count)
				for j := range localoffsets {
					localoffsets[j], err = r.ReadInt32()
					if err != nil {
						return err
					}
				}
			}

			thispos := ad.position + int64(localoffsets[i])

			_, err = r.Seek(int64(thispos), io.SeekStart)
			if err != nil {
				ui.Error().Msgf("AD Explorer reader seeking to %v failed: %v, UTF16 string skipped", thispos, err)
				continue
				// return err
			}

			var wc WCstring
			err = r.Unmarshal(&wc)
			if err != nil {
				return err
			}
			value = string(wc)
		case ADSTYPE_OCTET_STRING, ADSTYPE_NT_SECURITY_DESCRIPTOR:
			// First read the lengths (store in localoffsets)
			if i == 0 {
				localoffsets = make([]int32, count)
				for i := range localoffsets {
					localoffsets[i], err = r.ReadInt32()
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
				value = "TRUE"
			} else {
				value = "FALSE"
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

		ad.results[i] = value
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
	pos, err := r.Seek(0, io.SeekCurrent)
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

	_, data, err := r.ReadBytes(int(length))
	if err != nil {
		return err
	}

	if len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}

	// Get the slice header
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&data))

	// The length and capacity of the slice are different.
	header.Len /= 2
	header.Cap /= 2

	// Convert slice header to an []int32
	udata := *(*[]uint16)(unsafe.Pointer(&header))

	result := WStringLength(string(utf16.Decode(udata)))
	*wsl = result

	return nil
}

type Wstring []uint16

func (w Wstring) String() string {
	return strings.TrimRight(string(utf16.Decode(w)), "\x00")
}

type WCstring string

func (wc *WCstring) BinaryDecode(r binstruct.Reader) error {
	var buffer []uint16
	for {
		if len(buffer) == cap(buffer) {
			newBuffer := make([]uint16, len(buffer), len(buffer)+64)
			copy(newBuffer, buffer)
			buffer = newBuffer
		}

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

type ADExplorerDumper struct {
	path        string
	performance bool

	rawfile *os.File
}

func (adex *ADExplorerDumper) Connect() error {
	var err error
	adex.rawfile, err = os.Open(adex.path)
	return err
}

func (adex *ADExplorerDumper) Disconnect() error {
	return adex.rawfile.Close()
}

func (adex *ADExplorerDumper) Dump(do DumpOptions) ([]activedirectory.RawObject, error) {
	var dec binstruct.Reader

	// Ordinary reader or in-memory reader for way better performance due to excessive seeks
	if !adex.performance {
		dec = binstruct.NewReader(adex.rawfile, binary.LittleEndian, false)
	} else {
		ui.Info().Msg("Loading raw AD Explorer snapshot into memory")
		adexplorerbytes, err := ioutil.ReadAll(adex.rawfile)
		if err != nil {
			return nil, fmt.Errorf("error reading ADExplorer file: %v", err)
		}
		bufreader := bytes.NewReader(adexplorerbytes)
		dec = binstruct.NewReader(bufreader, binary.LittleEndian, false)
	}

	// Header
	ui.Info().Msg("Reading header (takes a while) ...")
	var header ADEXHeader
	err := dec.Unmarshal(&header)

	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	if header.Signature != "win-ad-ob" {
		return nil, fmt.Errorf("invalid AD Explorer data file signature: %v", header.Signature)
	}

	if header.Version != 0x00010001 {
		return nil, fmt.Errorf("invalid AD Explorer data file marker: %v", header.Version)
	}

	var e *msgp.Writer
	if do.WriteToFile != "" {
		err = os.MkdirAll(filepath.Dir(do.WriteToFile), 0755)
		if err != nil {
			return nil, fmt.Errorf("problem creating directory: %v", err)
		}
		outfile, err := os.Create(do.WriteToFile)
		if err != nil {
			return nil, fmt.Errorf("problem opening domain cache file: %v", err)
		}
		defer outfile.Close()

		boutfile := lz4.NewWriter(outfile)
		lz4options := []lz4.Option{
			lz4.BlockChecksumOption(true),
			// lz4.BlockSizeOption(lz4.BlockSize(51 * 1024)),
			lz4.ChecksumOption(true),
			lz4.CompressionLevelOption(lz4.Level9),
			lz4.ConcurrencyOption(-1),
		}
		boutfile.Apply(lz4options...)
		defer boutfile.Close()
		e = msgp.NewWriter(boutfile)
	}

	bar := ui.ProgressBar("Converting objects from AD Explorer snapshot", int64(header.ObjectCount))

	var objects []activedirectory.RawObject

	if do.ReturnObjects {
		objects = make([]activedirectory.RawObject, header.ObjectCount)
	}

	offsetcache := make(map[int64][]string)

	for i, ado := range header.Objects {
		var item activedirectory.RawObject
		item.Attributes, err = ado.GetValues(dec, header.Properties.Props, offsetcache)
		if err != nil {
			return nil, fmt.Errorf("failed to get values for object %d: %v", i, err)
		}

		item.DistinguishedName = item.Attributes["distinguishedName"][0]

		if e != nil {
			err = item.EncodeMsg(e)
			if err != nil {
				return nil, fmt.Errorf("problem encoding LDAP object %v: %v", item.DistinguishedName, err)
			}
		}

		if do.OnObject != nil {
			do.OnObject(&item)
		}

		if do.ReturnObjects {
			objects[i] = item
		}

		bar.Add(1)
	}

	bar.Finish()
	if e != nil {
		e.Flush()
	}

	return objects, err
}
