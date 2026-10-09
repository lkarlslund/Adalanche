package frontend

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"

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

func normalizePreferenceValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			out[key] = normalizePreferenceValue(nested)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			out[fmt.Sprint(key)] = normalizePreferenceValue(nested)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, nested := range typed {
			out[i] = normalizePreferenceValue(nested)
		}
		return out
	case []string:
		out := make([]any, len(typed))
		for i, nested := range typed {
			out[i] = nested
		}
		return out
	case []int:
		out := make([]any, len(typed))
		for i, nested := range typed {
			out[i] = nested
		}
		return out
	case []float64:
		out := make([]any, len(typed))
		for i, nested := range typed {
			out[i] = nested
		}
		return out
	case []bool:
		out := make([]any, len(typed))
		for i, nested := range typed {
			out[i] = nested
		}
		return out
	default:
		return value
	}
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
				if !yield(pref.Name, normalizePreferenceValue(pref.Value)) {
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
	preferences.GET("/:key", func(c *gin.Context) {
		key := c.Param("key")
		pref, found := sb.Get(key)
		if !found {
			return
		}
		out, _ := json.Marshal(normalizePreferenceValue(pref.Value))
		c.Writer.Write(out)
	})
	preferences.PUT("/:key", func(c *gin.Context) {
		key := c.Param("key")
		var value any
		if err := c.ShouldBindJSON(&value); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		sb.Put(Preference{Name: key, Value: value})
		c.Status(http.StatusNoContent)
	})
}
