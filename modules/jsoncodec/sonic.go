//go:build amd64 || arm64

package jsoncodec

import (
	"io"

	"github.com/bytedance/sonic"
)

// JSON encodes with sonic, which needs a 64-bit platform.
var JSON Codec = sonicCodec{}

var sonicAPI = sonic.ConfigStd

type sonicCodec struct{}

func (sonicCodec) Marshal(v any) ([]byte, error)      { return sonicAPI.Marshal(v) }
func (sonicCodec) Unmarshal(data []byte, v any) error { return sonicAPI.Unmarshal(data, v) }
func (sonicCodec) MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return sonicAPI.MarshalIndent(v, prefix, indent)
}
func (sonicCodec) NewEncoder(w io.Writer) Encoder { return sonicAPI.NewEncoder(w) }
func (sonicCodec) NewDecoder(r io.Reader) Decoder { return sonicAPI.NewDecoder(r) }
