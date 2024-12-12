package frontend

import (
	"encoding/json"
	"maps"

	"github.com/gin-gonic/gin"
	"github.com/lkarlslund/adalanche/modules/persistence"
)

type Preference struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

func (p Preference) ID() string {
	return p.Name
}

func AddPreferencesEndpoints(ws *WebService) {
	// Saved preferences
	sb := persistence.GetStorage[Preference]("preferences", false)

	preferences := ws.API.Group("preferences")

	preferences.GET("", func(c *gin.Context) {
		prefs, err := sb.List()
		if err != nil {
			return
		}
		prefsmap := maps.Collect[string, any](func(yield func(string, any) bool) {
			for _, pref := range prefs {
				if !yield(pref.Name, pref.Value) {
					break
				}
			}
		})
		c.JSON(200, prefsmap)
	})
	preferences.POST("", func(c *gin.Context) {
		var prefsmap = make(map[string]any)
		err := c.BindJSON(&prefsmap)
		if err != nil {
			c.String(500, err.Error())
		}
		for key, value := range prefsmap {
			sb.Put(Preference{Name: key, Value: value})
		}
	})
	preferences.GET(":key", func(c *gin.Context) {
		key := c.Param("key")
		pref, found := sb.Get(key)
		if !found {
			return
		}
		out, _ := json.Marshal(pref.Value)
		c.Writer.Write(out)
	})
	preferences.GET(":key/:value", func(c *gin.Context) {
		key := c.Param("key")
		value := c.Param("value")
		sb.Put(Preference{Name: key, Value: value})
	})
}
