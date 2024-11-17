package frontend

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/gorilla/websocket"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/lkarlslund/adalanche/modules/settings"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func AddUIEndpoints(ws *WebService) {
	// Lists available edges that Adalanche understands - this allows us to expand functionality
	// in the code, without touching the HTML
	backend := ws.API.Group("backend")

	backend.GET("filteroptions", func(c *gin.Context) {
		type filterinfo struct {
			Name            string `json:"name"`
			Lookup          string `json:"lookup"`
			Description     string `json:"description"`
			DefaultEnabledF bool   `json:"defaultenabled_f"`
			DefaultEnabledM bool   `json:"defaultenabled_m"`
			DefaultEnabledL bool   `json:"defaultenabled_l"`
		}
		type returnobject struct {
			ObjectTypes []filterinfo `json:"objecttypes"`
			Methods     []filterinfo `json:"edges"`
		}
		var results returnobject

		for _, edge := range engine.Edges() {
			if !edge.IsHidden() {
				results.Methods = append(results.Methods, filterinfo{
					Name:            edge.String(),
					Lookup:          edge.String(),
					DefaultEnabledF: edge.DefaultF(),
					DefaultEnabledM: edge.DefaultM(),
					DefaultEnabledL: edge.DefaultL(),
				})
			}
		}

		for _, objecttype := range engine.ObjectTypes() {
			results.ObjectTypes = append(results.ObjectTypes, filterinfo{
				Name:            objecttype.Name,
				Lookup:          objecttype.Lookup,
				DefaultEnabledF: objecttype.DefaultEnabledF,
				DefaultEnabledM: objecttype.DefaultEnabledM,
				DefaultEnabledL: objecttype.DefaultEnabledL,
			})
		}

		c.JSON(200, results)
	})
	// Checks a LDAP style query for input errors, and returns a hint to the user
	// It supports the include,exclude syntax specific to this program
	backend.GET("validatequery", func(c *gin.Context) {
		querytext := strings.Trim(c.Query("query"), " \n\r")
		if querytext != "" {
			_, err := query.ParseLDAPQueryStrict(querytext, ws.Objs)
			if err != nil {
				c.String(500, err.Error())
				return
			}
		}
		c.JSON(200, gin.H{"success": true})
	})

	backend.GET("types", func(c *gin.Context) {
		c.JSON(200, typeInfos)
	})

	backend.GET("statistics", func(c *gin.Context) {
		var result struct {
			Adalanche  map[string]string `json:"adalanche"`
			Statistics map[string]int    `json:"statistics"`
		}
		result.Adalanche = make(map[string]string)
		result.Adalanche["shortversion"] = version.VersionStringShort()
		result.Adalanche["program"] = version.Program
		result.Adalanche["version"] = version.Version
		result.Adalanche["commit"] = version.Commit
		result.Adalanche["status"] = ws.status.String()

		result.Statistics = make(map[string]int)

		if ws.Objs != nil {
			for objecttype, count := range ws.Objs.Statistics() {
				if objecttype == 0 {
					continue // skip the dummy one
				}
				if count == 0 {
					continue
				}
				result.Statistics[engine.ObjectType(objecttype).String()] += count
			}
			var edgeCount int
			ws.Objs.Iterate(func(object *engine.Object) bool {
				edgeCount += object.Edges(engine.Out).Len()
				return true
			})
			result.Statistics["Total"] = ws.Objs.Len()
			result.Statistics["PwnConnections"] = edgeCount
		}

		c.JSON(200, result)
	})

	backend.GET("progress", func(c *gin.Context) {
		var upgrader = websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var lastpbr []ui.ProgressReport
		var skipcounter int
		for {
			time.Sleep(250 * time.Millisecond)
			pbr := ui.GetProgressReport()
			sort.Slice(pbr, func(i, j int) bool {
				return pbr[i].StartTime.Before(pbr[j].StartTime)
			})

			if reflect.DeepEqual(lastpbr, pbr) {
				skipcounter++
				if skipcounter < 120 {
					continue
				}
			}
			skipcounter = 0

			output := struct {
				Status   string              `json:"status"`
				Progress []ui.ProgressReport `json:"progressbars"`
			}{
				Status:   ws.status.String(),
				Progress: pbr,
			}

			conn.SetWriteDeadline(time.Now().Add(time.Second * 15))
			err = conn.WriteJSON(output)
			if err != nil {
				return
			}

			lastpbr = pbr
		}
	})

	// Ready status
	backend.GET("status", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": ws.status.String()})
	})
	backend.GET("await/:status", func(c *gin.Context) {
		waitfor, err := WebServiceStatusString(c.Param("status"))
		if err != nil {
			c.Status(500)
			return
		}

		for ws.status != waitfor {
			time.Sleep(time.Millisecond * 10)
		}

		c.JSON(200, gin.H{"status": ws.status.String()})
	})

	// Shutdown
	backend.GET("quit", func(c *gin.Context) {
		ws.quit <- true
	})

}

func AddPreferencesEndpoints(ws *WebService) {
	// Saved preferences
	err := settings.Load()
	if err != nil {
		ui.Warn().Msgf("Problem loading preferences: %v", err)
	}

	preferences := ws.API.Group("preferences")

	preferences.GET("", func(c *gin.Context) {
		c.JSON(200, settings.All())
	})
	preferences.POST("", func(c *gin.Context) {
		var prefsmap = make(map[string]any)
		err := c.BindJSON(&prefsmap)
		if err != nil {
			c.String(500, err.Error())
		}

		for key, value := range prefsmap {
			settings.Set(key, value)
		}
		settings.Save()
	})

	preferences.GET(":key", func(c *gin.Context) {
		key := c.Param("key")
		out, _ := json.Marshal(settings.Get(key))
		c.Writer.Write(out)
	})

	preferences.GET(":key/:value", func(c *gin.Context) {
		key := c.Param("key")
		value := c.Param("value")
		settings.Set(key, value)
		settings.Save()
	})
}

func AddDataEndpoints(ws *WebService) {
	api := ws.API

	// Returns JSON describing an object located by distinguishedName, sid or guid
	api.GET("details/:locateby/:id", ws.RequireData(Ready), func(c *gin.Context) {
		var o *engine.Object
		var found bool
		switch strings.ToLower(c.Param("locateby")) {
		case "id":
			id, err := strconv.Atoi(c.Param("id"))
			if err != nil {
				c.String(500, err.Error())
				return
			}
			o, found = ws.Objs.FindID(engine.ObjectID(id))
		case "dn", "distinguishedname":
			o, found = ws.Objs.Find(activedirectory.DistinguishedName, engine.AttributeValueString(c.Param("id")))
		case "sid":
			sid, err := windowssecurity.ParseStringSID(c.Param("id"))
			if err != nil {
				c.String(500, err.Error())
				return
			}
			o, found = ws.Objs.Find(activedirectory.ObjectSid, engine.AttributeValueSID(sid))
		case "guid":
			u, err := uuid.FromString(c.Param("id"))
			if err != nil {
				c.String(500, err.Error())
				return
			}
			o, found = ws.Objs.Find(activedirectory.ObjectGUID, engine.AttributeValueGUID(u))
		}
		if !found {
			c.AbortWithStatus(404)
			return
		}

		if c.Query("format") == "objectdump" {
			c.Writer.Write([]byte(o.StringACL(ws.Objs)))
			return
		}

		// default format

		type ObjectDetails struct {
			DistinguishedName string              `json:"distinguishedname"`
			Attributes        map[string][]string `json:"attributes"`
			CanPwn            map[string][]string `json:"can_pwn"`
			PwnableBy         map[string][]string `json:"pwnable_by"`
		}

		od := ObjectDetails{
			DistinguishedName: o.DN(),
			Attributes:        make(map[string][]string),
		}

		o.AttrIterator(func(attr engine.Attribute, values engine.AttributeValues) bool {
			slice := values.StringSlice()
			for i := range slice {
				if !util.IsASCII(slice[i]) {
					slice[i] = util.Hexify(slice[i])
				}
				if len(slice[i]) > 256 {
					slice[i] = slice[i][:256] + " ..."
				}
			}
			sort.StringSlice(slice).Sort()
			od.Attributes[attr.String()] = slice
			return true
		})

		if c.Query("format") == "json" {
			c.JSON(200, od.Attributes)
			return
		}

		c.JSON(200, od)
	})

	api.GET("tree", ws.RequireData(Ready), func(c *gin.Context) {
		idstr := c.Query("id")

		var children engine.ObjectSlice
		if idstr == "#" {
			children = ws.Objs.Root().Children()
		} else {
			id, err := strconv.Atoi(idstr)
			if err != nil {
				c.String(400, "Problem converting id %v: %v", idstr, err)
				return
			}

			if parent, found := ws.Objs.FindID(engine.ObjectID(id)); found {
				children = parent.Children()
			} else {
				c.String(404, "object not found")
				return
			}
		}

		type treeData struct {
			Label    string          `json:"text"`
			Type     string          `json:"type,omitempty"`
			ID       engine.ObjectID `json:"id"`
			Children bool            `json:"children,omitempty"`
		}

		var results []treeData
		children.Iterate(func(object *engine.Object) bool {
			results = append(results, treeData{
				ID:       object.ID(),
				Label:    object.Label(),
				Type:     object.Type().String(),
				Children: object.Children().Len() > 0,
			})
			return true
		})

		c.JSON(200, results)
	})

	api.GET("export-words", ws.RequireData(Ready), func(c *gin.Context) {
		split := c.Query("split") == "true"

		// Set header for download as a text file
		c.Header("Content-Type", "text/plain")
		c.Header("Content-Disposition", "attachment; filename=adalanche-wordlist.txt")

		scrapeatttributes := []engine.Attribute{
			engine.DistinguishedName,
			engine.LookupAttribute("name"),
			engine.LookupAttribute("displayName"),
			engine.LookupAttribute("adminDescription"),
			engine.LookupAttribute("company"),
			engine.LookupAttribute("co"),
			engine.LookupAttribute("department"),
			engine.LookupAttribute("description"),
			engine.LookupAttribute("extensionAttribute1"),
			engine.LookupAttribute("extensionAttribute2"),
			engine.LookupAttribute("extensionAttribute3"),
			engine.LookupAttribute("extensionAttribute4"),
			engine.LookupAttribute("extensionAttribute5"),
			engine.LookupAttribute("extensionAttribute6"),
			engine.LookupAttribute("extensionAttribute7"),
			engine.LookupAttribute("extensionAttribute8"),
			engine.LookupAttribute("extensionAttribute9"),
			engine.LookupAttribute("extensionAttribute10"),
			engine.LookupAttribute("extensionAttribute11"),
			engine.LookupAttribute("extensionAttribute12"),
			engine.LookupAttribute("extensionAttribute13"),
			engine.LookupAttribute("extensionAttribute14"),
			engine.LookupAttribute("extensionAttribute15"),
			engine.LookupAttribute("extraColumns"),
			engine.LookupAttribute("givenName"),
			engine.LookupAttribute("importedFrom"),
			engine.LookupAttribute("l"),
			engine.LookupAttribute("mail"),
			engine.LookupAttribute("mailNickname"),
			engine.LookupAttribute("mobile"),
			engine.LookupAttribute("msRTCSIP-Line"),
			engine.LookupAttribute("msRTCSIP"),
			engine.LookupAttribute("ou"),
			engine.LookupAttribute("physicalDeliveryOfficeName"),
			engine.LookupAttribute("postalCode"),
			engine.LookupAttribute("proxyAddresses"),
			engine.LookupAttribute("sAMAccountName"),
			engine.LookupAttribute("sn"),
			engine.LookupAttribute("streetAddress"),
			engine.LookupAttribute("targetAddress"),
			engine.LookupAttribute("title"),
			engine.LookupAttribute("userPrincipalName"),
		}

		pb := ui.ProgressBar("Extracting words", int64(ws.Objs.Len()))
		wordmap := make(map[string]struct{})
		ws.Objs.Iterate(func(object *engine.Object) bool {
			pb.Add(1)
			for _, attr := range scrapeatttributes {
				if attr != engine.NonExistingAttribute {
					values, found := object.Get(attr)
					if found {
						values.Iterate(func(val engine.AttributeValue) bool {
							for _, word := range extractwords(val.String(), split) {
								wordmap[strings.Trim(word, " \n\r\t")] = struct{}{}
							}
							return true
						})
					}
				}
			}
			return true
		})
		pb.Finish()
		words := make([]string, 0, len(wordmap))
		for word := range wordmap {
			words = append(words, word)
		}
		slices.Sort(words)
		for _, word := range words {
			fmt.Fprintf(c.Writer, "%s\n", word)
		}
	})
}

func extractwords(input string, split bool) []string {
	result := []string{input}
	if split {
		result = append(result, strings.FieldsFunc(input, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == ';' || r == ':' || r == '.' || r == '!' || r == '?' || r == '(' || r == ')' || r == '{' || r == '}' || r == '[' || r == ']' || r == '&' || r == '|' || r == '^' || r == '+' || r == '-' || r == '=' || r == '/' || r == '*' || r == '%' || r == '<' || r == '>' || r == '~'
		})...)
	}
	return result
}
