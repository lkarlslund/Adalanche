package collect

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Velocidex/ordereddict"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"www.velocidex.com/golang/go-ese/parser"
)

type NTDSDumper struct {
	rawfile *os.File
	ese     *parser.ESEContext
	path    string
}

func (ntds *NTDSDumper) Connect() error {
	var err error
	ntds.rawfile, err = os.Open(ntds.path)
	if err != nil {
		return err
	}
	ntds.ese, err = parser.NewESEContext(ntds.rawfile)
	return err
}
func (ntds *NTDSDumper) Disconnect() error {
	return ntds.rawfile.Close()
}

type Table struct {
	Fields map[int64]string
	Name   string
}

func (ntds *NTDSDumper) DebugDump() error {
	// Initialize the catalog
	catalog, err := parser.ReadCatalog(ntds.ese)
	if err != nil {
		return err
	}
	output, _ := os.Create(ntds.path + ".txt")
	bufout := bufio.NewWriter(output)
	tables := catalog.Tables.Keys()
	for _, t := range tables {
		count := 0
		fmt.Fprintln(bufout, "-----------------------------", t, "----------------------------")
		err = catalog.DumpTable(t, func(row *ordereddict.Dict) error {
			serialized, err := json.Marshal(row)
			if err != nil {
				return err
			}
			count++
			fmt.Fprintf(bufout, "%v\n", string(serialized))
			return nil
		})
	}
	bufout.Flush()
	output.Close()
	return nil
}
func (ntds *NTDSDumper) Dump(do DumpOptions) ([]activedirectory.RawObject, error) {
	// Initialize the catalog
	catalog, err := parser.ReadCatalog(ntds.ese)
	if err != nil {
		return nil, err
	}
	// Load all Security Descriptors
	sdmap := make(map[int64]string)
	err = catalog.DumpTable("sd_table", func(row *ordereddict.Dict) error {
		id, _ := row.GetInt64("sd_id")
		hexvalue, loaded := row.Get("sd_value")
		if !loaded {
			ui.Error().Msgf("Error getting SD %v value: %v", id, err)
			return nil
		}
		value, err := hex.DecodeString(hexvalue.(string))
		if err != nil {
			ui.Error().Msgf("Error hex decoding SD %v: %v", hexvalue, err)
		}
		sdmap[id] = string(value)
		return nil
	})
	// Load schema information
	fieldnumtoname := make(map[int64]string)
	namemap := make(map[int64]string)
	ancestormap := make(map[int64]string)
	objectClassMap := make(map[int64]string)
	categoryMap := make(map[int64]string)
	attributeMap := make(map[int64]string)
	linknames := make(map[int64]string)
	var count int64
	err = catalog.DumpTable("datatable", func(row *ordereddict.Dict) error {
		// Name map for RDNs
		dnt, ok := row.GetInt64("DNT_col")
		if !ok {
			ui.Error().Msgf("No DNT_col for row %v", row)
			return nil
		}
		// Field displayname mapping
		displayname, _ := row.GetString("ATTm131532") // LDAP-Display-Name
		// ATT Field number
		if fieldnum, ok := row.GetInt64("ATTc131102"); ok { // ATT?fieldnum;
			fieldnumtoname[fieldnum] = displayname
			if displayname == "categoryId" {
				ui.Info().Msgf("categoryID is field %v", fieldnum)
			}
		}
		for _, key := range row.Keys() {
			if strings.HasSuffix(key, "590146") {
				ui.Info().Msg(key)
			}
		}
		if categoryID, ok := row.GetInt64("ATTb590146"); ok { // ATT?fieldnum;
			categoryMap[categoryID] = displayname
		}
		if attributeID, ok := row.GetInt64("ATTc131102"); ok { // ATT?fieldnum;
			attributeMap[attributeID] = displayname
		}
		if governsID, ok := row.GetInt64("ATTc131094"); ok { // ATT?fieldnum;
			objectClassMap[governsID] = displayname
		}
		// LinkID to attribute name
		if linkid, ok := row.GetInt64("ATTj131122"); ok { // LinkID
			// ui.Debug().Msgf("LinkID %v -> %v", linkid, displayname)
			linknames[linkid] = displayname
		}
		if name, ok := row.GetString("ATTm589825"); ok { // Object name?
			var prefix string
			RDNtyp, _ := row.GetInt64("RDNtyp_col")
			switch RDNtyp {
			case 3:
				prefix = "CN="
			case 10:
				prefix = "O="
			case 11:
				prefix = "OU="
			case 1376281:
				prefix = "DC="
			case 707406378:
				// $NOT_AN_OBJECT1$
			default:
				prefix = "??="
				ui.Warn().Msgf("Unknown prefix value %v mapped for %v", RDNtyp, name)
			}
			namemap[dnt] = prefix + name
		}
		// Ancestors
		if ancestors, ok := row.GetString("Ancestors_col"); ok {
			ancestormap[dnt] = ancestors
		}
		count++
		return nil
	})
	if err != nil {
		return nil, err
	}
	/*
		err = catalog.DumpTable("datatable", func(row *ordereddict.Dict) error {
			// Find distinguished name
			var dn string
			if rdn, ok := row.GetString("Ancestors_col"); ok {
				dn = getDistinguishedName(rdn, namemap)
			} else {
				return nil
			}
		fieldloop:
			for _, fieldname := range row.Keys() {
				usedname := fieldname
				var fieldtype byte
				if len(fieldname) >= 5 && strings.HasPrefix(fieldname, "ATT") {
					// Translate name
					var found bool
					fieldnum, _ := strconv.ParseInt(fieldname[4:], 10, 64)
					usedname, found = fieldnumtoname[fieldnum]
					if !found {
						ui.Error().Msgf("Failed to find field name for %v", fieldname)
						continue
					}
					fieldtype = fieldname[3]
				} else {
					// ui.Error().Msgf("Unmappable field name for %v", fieldname)
					continue
				}
				_ = fieldtype

				switch usedname {
				case "governsID":
					if gs, found := row.GetInt64(fieldname); found {
						objectClassMap[gs] = dn
					}
					break fieldloop
				case "attributeID":
					if gs, found := row.GetInt64(fieldname); found {
						attributeMap[gs] = dn
					}
				}
			}

			return nil
		})
	*/

	// Resolve groups and members
	type linkInfo struct {
		source   int64
		linkbase int64
	}
	linkmap := make(map[linkInfo][]int64)
	err = catalog.DumpTable("link_table", func(row *ordereddict.Dict) error {
		// Field name mapping
		if dt, ok := row.GetInt64("link_deltime"); ok && dt != 0x2A2A2A2A2A2A2A2A {
			ui.Warn().Msgf("link_deltime in link_table is %v", dt)
			return nil // deleted
		}
		link, ok := row.GetInt64("link_DNT") // ATT?fieldnum
		if !ok {
			return nil
		}
		backlink, ok := row.GetInt64("backlink_DNT")
		if !ok {
			return nil
		}
		linkbase, _ := row.GetInt64("link_base")
		// forward links
		l := linkInfo{
			source:   link,
			linkbase: linkbase * 2,
		}
		members := linkmap[l]
		members = append(members, backlink)
		linkmap[l] = members
		// reverse links
		l2 := linkInfo{
			source:   backlink,
			linkbase: linkbase*2 + 1,
		}
		reverselink := linkmap[l2]
		reverselink = append(reverselink, link)
		linkmap[l2] = reverselink
		return nil
	})
	// Dump it
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
	var objects []activedirectory.RawObject
	// fmt.Println(catalog.Dump())
	err = catalog.DumpTable("datatable", func(row *ordereddict.Dict) error {
		var item activedirectory.RawObject
		item.Init()
		// Find distinguished name
		if rdn, ok := row.GetString("Ancestors_col"); ok {
			item.DistinguishedName = getDistinguishedName(rdn, namemap)
		}
	recordloop:
		for _, fieldname := range row.Keys() {
			// Extract field number
			usedname := fieldname
			var fieldtype byte
			if len(fieldname) >= 5 && strings.HasPrefix(fieldname, "ATT") {
				// Translate name
				var found bool
				fieldnum, _ := strconv.ParseInt(fieldname[4:], 10, 64)
				usedname, found = fieldnumtoname[fieldnum]
				if !found {
					ui.Error().Msgf("Failed to find field name for %v", fieldname)
					continue
				}
				fieldtype = fieldname[3]
			} else {
				// ui.Error().Msgf("Unmappable field name for %v", fieldname)
				continue
			}
			var resultval []string
			rawvalue, ok := row.Get(fieldname)
			if !ok {
				ui.Warn().Msgf("Problem getting field value for field %v (%v) for %v", fieldname, usedname, item.DistinguishedName)
				continue
			}
			var processvalues []any
			if values, ok := rawvalue.([]any); ok {
				processvalues = values
			} else {
				processvalues = []any{rawvalue}
			}
			for _, value := range processvalues {
				// if fmt.Sprintf("%v", value) == "1554" && strings.Contains(item.DistinguishedName, "Person") {
				// 	ui.Info().Msgf("Field %v %v %v", item.DistinguishedName, fieldname, usedname)
				// }
				switch string(fieldtype) {
				case "m":
					// plain string
				case "p":
					hexIndex, ok := row.GetString(fieldname)
					if !ok {
						i, _ := row.Get(fieldname)
						ui.Error().Msgf("Failed to retrieve security descriptor value for %v (%v)", item.DistinguishedName, i)
						continue
					}
					sdIndex, err := hexUint64(hexIndex)
					if err != nil {
						ui.Error().Msgf("Failed to parse security descriptor index %v: %v", hexIndex, err)
						continue
					}
					securityDescriptor, found := sdmap[int64(sdIndex)]
					if !found {
						ui.Error().Msgf("Failed to lookup security descriptor %v value for %v", sdIndex, item.DistinguishedName)
						continue
					}
					resultval = append(resultval, securityDescriptor)
				case "k", "r", "h":
					decoded, err := hex.DecodeString(value.(string))
					if err != nil {
						ui.Error().Msgf("Failed to decode hex string %v: %v", value, err)
					} else {
						resultval = append(resultval, string(decoded))
					}
				case "c", "i", "j", "l", "q", "b":
					if usedname == "distinguishedName" {
						resultval = []string{item.DistinguishedName} // Handled differently
						continue                                     // handled differently
					}
					switch usedname {
					case "isDeleted":
						if isdeleted, ok := value.(int32); ok && isdeleted == 1 {
							// Deleted, so skip importing it
							continue recordloop
						}
					case "subRefs":
						// ignore for now
					case "objectClassCategory":
						if intValue, ok := value.(int32); ok {
							switch intValue {
							case 0:
								// bork!
								ui.Debug().Msgf("Object %v objectClassCategory value 0 is suspicious", item.DistinguishedName)
							case 1:
								resultval = []string{"STRUCTURAL"}
							case 2:
								resultval = []string{"ABSTRACT"}
							case 3:
								resultval = []string{"AUXILLARY"}
							default:
								ui.Error().Msgf("Unknown objectClassCategory value %v", intValue)
							}
						} else {
							ui.Warn().Msgf("Problem getting int32 value, for %T", value)
						}
					case "objectCategory", "defaultObjectCategory":
						if intValue, ok := value.(int32); ok {
							if name, found := namemap[int64(intValue)]; found {
								// ui.Info().Msgf("Name %v", name)
								_, name, _ := strings.Cut(name, "=") // remove CN= etc
								resultval = append(resultval, name)
								// }
								// if lookupVal, ok := row.GetString(fieldname); ok {
								// 	dn := getDistinguishedName(lookupVal, namemap)
								// 	resultval = append(resultval, dn)
							} else {
								ui.Warn().Msgf("%v lookup value %v not found for %v, skipping", usedname, intValue, item.DistinguishedName)
							}
						} else {
							ui.Warn().Msgf("Expected int32 for lookup on classes in field %v for %v", usedname, item.DistinguishedName)
						}
					case "objectClass", "possSuperiors", "systemPossSuperiors", "systemAuxiliaryClass", "auxiliaryClass":
						if intValue, ok := value.(int32); ok {
							if lookupVal, found := objectClassMap[int64(intValue)]; found {
								resultval = append(resultval, lookupVal)
							} else {
								ui.Warn().Msgf("%v lookup value %v not found for %v, skipping", usedname, intValue, item.DistinguishedName)
							}
						} else {
							ui.Warn().Msgf("Expected int32 for lookup on classes in field %v for %v", usedname, item.DistinguishedName)
						}
					case "mustContain", "mayContain", "systemMustContain", "systemMayContain":
						if intValue, ok := value.(int32); ok {
							if lookupVal, found := attributeMap[int64(intValue)]; found {
								resultval = append(resultval, lookupVal)
							} else {
								ui.Warn().Msgf("%v lookup value %v not found for %v, skipping", usedname, intValue, item.DistinguishedName)
							}
						} else {
							ui.Warn().Msgf("Expected int32 for lookup on classes in field %v for %v", usedname, item.DistinguishedName)
						}
					case "dsCorePropagationData", "whenCreated", "whenChanged":
						// FIXME
						// if intValue, ok := value.(uint64); ok && intValue > 1 {
						// 	// swap endianness in uint64
						// 	bytes := make([]byte, 8)
						// 	// binary.LittleEndian.PutUint64(bytes, intValue)
						// 	binary.BigEndian.PutUint64(bytes, intValue)
						// 	// intValue = binary.BigEndian.Uint64(bytes)
						// 	time := parser.WinFileTime64Bin(bytes)
						// 	// time := util.FiletimeToTime(intValue)
						// 	ui.Info().Msgf("Time is %v", time)
						// 	resultval = append(resultval, time.Format("20060102150405"))
						// }
					default:
						resultval = append(resultval, fmt.Sprintf("%v", value))
					}
				default:
					ui.Error().Msgf("Unhandled field %v type %v (contains %T: %v)", usedname, string(fieldtype), value, value)
					continue recordloop
				}
			}
			if len(resultval) > 0 {
				item.Attributes[usedname] = resultval
			}
		}
		// does it have members?
		dnt, ok := row.GetInt64("DNT_col")
		if ok {
			for l, pointsto := range linkmap {
				if l.source == dnt {
					linktargets := make([]string, 0, len(pointsto))
					for _, m := range pointsto {
						ancestor, found := ancestormap[m]
						if !found {
							ui.Error().Msgf("Failed to find ancestor for %v", m)
						} else {
							linktargets = append(linktargets, getDistinguishedName(ancestor, namemap))
						}
					}
					// Add the members
					attrname, found := linknames[l.linkbase]
					if !found {
						ui.Error().Msgf("Failed to find link attribute %v from %v to %v", l.linkbase, item.DistinguishedName, strings.Join(linktargets, ", "))
					} else {
						item.Attributes[attrname] = linktargets
						// ui.Debug().Msgf("Adding link attribute %v %v to %v", attrname, linktargets, item.DistinguishedName)
					}
				}
			}
		}
		oc := item.Attributes["objectClass"]
		if item.DistinguishedName == "CN=Top,CN=Schema,CN=Configuration,DC=sevenkingdoms,DC=local" {
			// ui.Debug().Msgf("Found schema: %v", item)
		} else if item.DistinguishedName == "CN=Person,CN=Schema,CN=Configuration,DC=sevenkingdoms,DC=local" {
			// ui.Debug().Msgf("Found person: %v", item)
		} else if item.DistinguishedName == "DC=sevenkingdoms,DC=local" {
			ui.Debug().Msgf("Found root: %v", item)
		} else if slices.Contains(oc, "crossRef") {
			ui.Debug().Msgf("Crossref: %v", item)
		}
		if do.OnObject != nil {
			do.OnObject(&item)
		}
		if do.ReturnObjects {
			objects = append(objects, item)
		}
		if e != nil {
			err = item.EncodeMsg(e)
			if err != nil {
				return fmt.Errorf("problem encoding LDAP object %v: %v", item.DistinguishedName, err)
			}
		}
		return nil
	})
	if e != nil {
		e.Flush()
	}
	return objects, err
}
func getDistinguishedName(rdnlist string, namemap map[int64]string) string {
	dn := ""
	for len(rdnlist) > 0 {
		currdnbin, _ := hex.DecodeString(rdnlist[:8])
		currdn := binary.LittleEndian.Uint32(currdnbin)
		name := namemap[int64(currdn)]
		rdnlist = rdnlist[8:]
		if name == "$ROOT_OBJECT$" {
			continue
		}
		if len(dn) > 0 {
			dn = "," + dn
		}
		dn = name + dn
	}
	return dn
}
func hexUint64(hexstring string) (uint64, error) {
	data, err := hex.DecodeString(hexstring)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}
func verifyTimeStamp(ts uint64) (uint64, error) {
	if ts < 120000000000000000 || ts >= 9223372036854775807 || ts == 0 {
		return 0, fmt.Errorf("invalid timestamp %v", ts)
	}
	return ts, nil
}
