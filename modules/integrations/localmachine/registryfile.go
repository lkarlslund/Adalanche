package localmachine

import (
	"errors"
	"fmt"

	"github.com/tinylib/msgp/msgp"
)

// Registry values have explicit type tags because compact integer encodings
// otherwise lose signedness and generic array decoding loses string-slice types.
func encodeRegistryValue(key string, value any) ([]byte, error) {
	b := msgp.AppendString(nil, key)
	switch v := value.(type) {
	case nil:
		return msgp.AppendString(b, "nil"), nil
	case uint64:
		return msgp.AppendUint64(msgp.AppendString(b, "uint64"), v), nil
	case int64:
		return msgp.AppendInt64(msgp.AppendString(b, "int64"), v), nil
	case float64:
		return msgp.AppendFloat64(msgp.AppendString(b, "float64"), v), nil
	case bool:
		return msgp.AppendBool(msgp.AppendString(b, "bool"), v), nil
	case string:
		return msgp.AppendString(msgp.AppendString(b, "string"), v), nil
	case []byte:
		return msgp.AppendBytes(msgp.AppendString(b, "bytes"), v), nil
	case []string:
		b = msgp.AppendArrayHeader(msgp.AppendString(b, "strings"), uint32(len(v)))
		for _, s := range v {
			b = msgp.AppendString(b, s)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("unsupported registry value type %T", value)
	}
}

func decodeRegistryValue(b []byte) (key string, value any, err error) {
	key, b, err = msgp.ReadStringBytes(b)
	if err != nil {
		return
	}
	var kind string
	kind, b, err = msgp.ReadStringBytes(b)
	if err != nil {
		return
	}
	switch kind {
	case "nil":
	case "uint64":
		value, b, err = msgp.ReadUint64Bytes(b)
	case "int64":
		value, b, err = msgp.ReadInt64Bytes(b)
	case "float64":
		value, b, err = msgp.ReadFloat64Bytes(b)
	case "bool":
		value, b, err = msgp.ReadBoolBytes(b)
	case "string":
		value, b, err = msgp.ReadStringBytes(b)
	case "bytes":
		value, b, err = msgp.ReadBytesBytes(b, nil)
	case "strings":
		var count uint32
		count, b, err = msgp.ReadArrayHeaderBytes(b)
		if err != nil {
			return
		}
		if uint64(count) > uint64(len(b)) {
			return "", nil, errors.New("invalid registry string count")
		}
		values := make([]string, int(count))
		for i := range values {
			values[i], b, err = msgp.ReadStringBytes(b)
			if err != nil {
				return
			}
		}
		value = values
	default:
		return "", nil, errors.New("unsupported registry value type")
	}
	if err == nil && len(b) != 0 {
		err = errors.New("trailing registry value data")
	}
	return
}
