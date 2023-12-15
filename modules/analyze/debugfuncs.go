package analyze

import (
	"encoding/json"
	"net/http"

	"github.com/lkarlslund/adalanche/modules/engine"
)

func debugfuncs(ws *webservice) {
	ws.Router.HandleFunc("/debug/attributes", func(w http.ResponseWriter, r *http.Request) {
		j, _ := json.Marshal(engine.AttributeInfos())
		w.Write(j)
	})
	ws.Router.HandleFunc("/debug/edges", func(w http.ResponseWriter, r *http.Request) {
		j, _ := json.Marshal(engine.EdgeInfos())
		w.Write(j)
	})
}
