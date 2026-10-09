package frontend

import (
	"io"

	ginjson "github.com/gin-gonic/gin/codec/json"
	"github.com/lkarlslund/adalanche/modules/jsoncodec"
)

// JSON is the web service's encoder; gin renders and binds with it too.
var JSON = jsoncodec.JSON

func init() {
	ginjson.API = ginCodec{}
}

type ginCodec struct{}

func (ginCodec) Marshal(v any) ([]byte, error)      { return JSON.Marshal(v) }
func (ginCodec) Unmarshal(data []byte, v any) error { return JSON.Unmarshal(data, v) }
func (ginCodec) MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return JSON.MarshalIndent(v, prefix, indent)
}
func (ginCodec) NewEncoder(w io.Writer) ginjson.Encoder { return JSON.NewEncoder(w) }
func (ginCodec) NewDecoder(r io.Reader) ginjson.Decoder { return JSON.NewDecoder(r) }
