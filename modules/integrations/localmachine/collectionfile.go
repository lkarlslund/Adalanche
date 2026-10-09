package localmachine

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/tinylib/msgp/msgp"
)

func init() {
	for _, schema := range []uint32{1, 2} {
		collection.RegisterValidator(collection.Machine, schema, ValidateMachineCollection)
	}
}

// WriteCollection stores the common machine record and optional, independently
// versioned extension records. Extensions must use the "extension:" prefix.
func WriteCollection(path string, info Info, extensions map[string][]byte, options ...collection.CreateOption) error {
	w, err := collection.Create(path, collection.Header{Kind: collection.Machine, Schema: 2, Collector: info.Common, Source: info.Machine.Name}, options...)
	if err != nil {
		return err
	}
	defer w.Abort()
	registry := info.RegistryData
	results := info.CollectionResults
	inventories := info
	info.RegistryData, info.CollectionResults = nil, nil
	info.LoginInfos = nil
	info.Network.NetworkInterfaces = nil
	info.Users = nil
	info.Groups = nil
	info.Shares = nil
	info.Services = nil
	info.Software = nil
	info.Tasks = nil
	info.Privileges = nil
	info.Machine.AppCache = nil
	payload, err := info.MarshalMsg(nil)
	if err != nil {
		return err
	}
	if err := w.Write("machine", payload); err != nil {
		return err
	}
	if err := writeMachineItems(w, "login", inventories.LoginInfos, (*LogonInfo).MarshalMsg); err != nil {
		return err
	}
	if err := writeMachineItems(w, "interface", inventories.Network.NetworkInterfaces, (*NetworkInterfaceInfo).MarshalMsg); err != nil {
		return err
	}
	if err := writeMachineItems(w, "user", inventories.Users, (*User).MarshalMsg); err != nil {
		return err
	}
	if err := writeMachineItems(w, "group", inventories.Groups, (*Group).MarshalMsg); err != nil {
		return err
	}
	if err := writeMachineItems(w, "share", inventories.Shares, (*Share).MarshalMsg); err != nil {
		return err
	}
	if err := writeMachineItems(w, "service", inventories.Services, (*Service).MarshalMsg); err != nil {
		return err
	}
	if err := writeMachineItems(w, "software", inventories.Software, (*Software).MarshalMsg); err != nil {
		return err
	}
	if err := writeMachineItems(w, "task", inventories.Tasks, (*RegisteredTask).MarshalMsg); err != nil {
		return err
	}
	if err := writeMachineItems(w, "privilege", inventories.Privileges, (*Privilege).MarshalMsg); err != nil {
		return err
	}
	for _, data := range inventories.Machine.AppCache {
		if err := w.Write("appcache", data); err != nil {
			return err
		}
	}
	resultKeys := make([]string, 0, len(results))
	for key := range results {
		resultKeys = append(resultKeys, key)
	}
	sort.Strings(resultKeys)
	for _, key := range resultKeys {
		result := results[key]
		data, err := result.MarshalMsg(msgp.AppendString(nil, key))
		if err != nil {
			return err
		}
		if err := w.Write("result", data); err != nil {
			return err
		}
	}
	registryKeys := make([]string, 0, len(registry))
	for key := range registry {
		registryKeys = append(registryKeys, key)
	}
	sort.Strings(registryKeys)
	for _, key := range registryKeys {
		payload, err := encodeRegistryValue(key, registry[key])
		if err != nil {
			return err
		}
		if err := w.Write("registry", payload); err != nil {
			return err
		}
	}
	keys := make([]string, 0, len(extensions))
	for name := range extensions {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		if !strings.HasPrefix(name, "extension:") {
			return errors.New("invalid machine extension name")
		}
		if err := w.Write(name, extensions[name]); err != nil {
			return err
		}
	}
	// Individual operation results are authoritative; older collection routines
	// do not yet record outcomes for every operation.
	if err := w.Write("machine-end", nil); err != nil {
		return err
	}
	return w.Commit(machineOutcome(results))
}

func ReadCollection(path string) (Info, map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return Info{}, nil, err
	}
	defer f.Close()
	var info Info
	if !strings.HasSuffix(path, collection.MachineSuffix) {
		err := json.NewDecoder(f).Decode(&info)
		return info, nil, err
	}
	r, err := collection.NewReader(f, collection.Machine)
	if err != nil {
		return Info{}, nil, err
	}
	defer r.Close()
	return readMachineRecords(r, true)
}

func machineOutcome(results basedata.CollectionResults) collection.Outcome {
	for _, result := range results {
		switch result.Status {
		case basedata.CollectionUnknown, basedata.CollectionCollected, basedata.CollectionNotRequested:
		default:
			return collection.Partial
		}
	}
	return collection.Unknown
}

func writeMachineItems[T any](w *collection.Writer, kind string, items []T, encode func(*T, []byte) ([]byte, error)) error {
	var data []byte
	for i := range items {
		var err error
		data, err = encode(&items[i], data[:0])
		if err != nil {
			return err
		}
		if err := w.Write(kind, data); err != nil {
			return err
		}
	}
	return nil
}

func decodeMachineItem[T any](data []byte, decode func(*T, []byte) ([]byte, error)) (T, error) {
	var result T
	rest, err := msgp.Skip(data)
	if err != nil {
		return result, err
	}
	if len(rest) != 0 {
		return result, errors.New("trailing machine record data")
	}
	rest, err = decode(&result, data)
	if err == nil && len(rest) != 0 {
		err = errors.New("trailing machine record data")
	}
	return result, err
}

// ValidateMachineCollection checks all typed records without retaining inventories.
func ValidateMachineCollection(r *collection.Reader) error {
	_, _, err := readMachineRecords(r, false)
	return err
}

func readMachineRecords(r *collection.Reader, retain bool) (Info, map[string][]byte, error) {
	if r.Header.Schema != 1 && r.Header.Schema != 2 {
		return Info{}, nil, errors.New("unsupported machine collection schema")
	}
	var info Info
	seen, ended := false, false
	extensions := make(map[string][]byte)
	registrySeen, resultsSeen := make(map[string]bool), make(map[string]bool)
	outcome := collection.Unknown
	for {
		kind, payload, err := r.Next()
		if err == io.EOF {
			if !seen || (r.Header.Schema == 2 && !ended) {
				return Info{}, nil, errors.New("unfinished machine records")
			}
			if r.Header.Schema == 2 && r.Completion.Outcome != outcome {
				return Info{}, nil, errors.New("machine outcome mismatch")
			}
			return info, extensions, nil
		}
		if err != nil {
			return Info{}, nil, err
		}
		if ended {
			return Info{}, nil, errors.New("records after machine completion")
		}
		if kind == "machine" {
			if seen {
				return Info{}, nil, errors.New("duplicate machine record")
			}
			info, err = decodeMachineItem(payload, (*Info).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if len(info.RegistryData) != 0 {
				return Info{}, nil, errors.New("registry values must use typed registry records")
			}
			if r.Header.Schema == 2 && (len(info.LoginInfos) != 0 || len(info.Network.NetworkInterfaces) != 0 || len(info.Users) != 0 || len(info.Groups) != 0 || len(info.Shares) != 0 || len(info.Services) != 0 || len(info.Software) != 0 || len(info.Tasks) != 0 || len(info.Privileges) != 0 || len(info.CollectionResults) != 0 || len(info.Machine.AppCache) != 0) {
				return Info{}, nil, errors.New("inventories must use section records")
			}
			seen = true
			continue
		}
		if !seen {
			return Info{}, nil, errors.New("record precedes machine metadata")
		}
		switch {
		case kind == "registry":
			key, value, err := decodeRegistryValue(payload)
			if err != nil {
				return Info{}, nil, err
			}
			if registrySeen[key] {
				return Info{}, nil, errors.New("duplicate registry value")
			}
			registrySeen[key] = true
			if retain {
				if info.RegistryData == nil {
					info.RegistryData = make(RegistryData)
				}
				info.RegistryData[key] = value
			}
		case strings.HasPrefix(kind, "extension:"):
			if _, exists := extensions[kind]; exists {
				return Info{}, nil, errors.New("duplicate machine extension")
			}
			if retain {
				extensions[kind] = append([]byte(nil), payload...)
			} else {
				extensions[kind] = nil
			}
		case kind == "machine-end" && r.Header.Schema == 2:
			if len(payload) != 0 {
				return Info{}, nil, errors.New("invalid machine end record")
			}
			ended = true
		case kind == "result" && r.Header.Schema == 2:
			key, data, err := msgp.ReadStringBytes(payload)
			if err != nil {
				return Info{}, nil, err
			}
			if resultsSeen[key] {
				return Info{}, nil, errors.New("duplicate collection result")
			}
			result, err := decodeMachineItem(data, (*basedata.CollectionResult).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			resultsSeen[key] = true
			if retain {
				if info.CollectionResults == nil {
					info.CollectionResults = make(basedata.CollectionResults)
				}
				info.CollectionResults[key] = result
			}
			if machineOutcome(basedata.CollectionResults{key: result}) == collection.Partial {
				outcome = collection.Partial
			}
		case kind == "appcache" && r.Header.Schema == 2:
			if retain {
				info.Machine.AppCache = append(info.Machine.AppCache, append([]byte(nil), payload...))
			}
		case kind == "login" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*LogonInfo).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.LoginInfos = append(info.LoginInfos, item)
			}
		case kind == "interface" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*NetworkInterfaceInfo).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.Network.NetworkInterfaces = append(info.Network.NetworkInterfaces, item)
			}
		case kind == "user" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*User).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.Users = append(info.Users, item)
			}
		case kind == "group" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*Group).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.Groups = append(info.Groups, item)
			}
		case kind == "share" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*Share).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.Shares = append(info.Shares, item)
			}
		case kind == "service" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*Service).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.Services = append(info.Services, item)
			}
		case kind == "software" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*Software).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.Software = append(info.Software, item)
			}
		case kind == "task" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*RegisteredTask).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.Tasks = append(info.Tasks, item)
			}
		case kind == "privilege" && r.Header.Schema == 2:
			item, err := decodeMachineItem(payload, (*Privilege).UnmarshalMsg)
			if err != nil {
				return Info{}, nil, err
			}
			if retain {
				info.Privileges = append(info.Privileges, item)
			}
		default:
			return Info{}, nil, errors.New("unsupported machine record type")
		}
	}
}
