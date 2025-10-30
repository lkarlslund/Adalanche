package frontend

import (
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
			Name           string `json:"name"`
			Lookup         string `json:"lookup"`
			Description    string `json:"description"`
			Explainer      string `json:"explainer"`
			DefaultEnabled bool   `json:"defaultenabled"`
		}
		type returnobject struct {
			ObjectTypes []filterinfo `json:"objecttypes"`
			Methods     []filterinfo `json:"edges"`
		}
		var results returnobject
		for _, edge := range engine.Edges() {
			if !edge.IsHidden() {
				results.Methods = append(results.Methods, filterinfo{
					Name:           edge.String(),
					Lookup:         edge.String(),
					DefaultEnabled: edge.DefaultF(),
				})
			}
		}
		for _, objecttype := range engine.NodeTypes() {
			results.ObjectTypes = append(results.ObjectTypes, filterinfo{
				Name:           objecttype.Name,
				Lookup:         objecttype.Lookup,
				DefaultEnabled: objecttype.DefaultEnabled,
			})
		}
		c.JSON(200, results)
	})
	// Checks a LDAP style query for input errors, and returns a hint to the user
	// It supports the include,exclude syntax specific to this program
	backend.GET("validatequery", func(c *gin.Context) {
		querytext := strings.Trim(c.Query("query"), " \n\r")
		if querytext != "" {
			_, err := query.ParseLDAPQueryStrict(querytext, ws.SuperGraph)
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
		if ws.SuperGraph != nil {
			for objecttype, count := range ws.SuperGraph.Statistics() {
				if objecttype == 0 {
					continue // skip the dummy one
				}
				if count == 0 {
					continue
				}
				result.Statistics[engine.NodeType(objecttype).String()] += count
			}
			result.Statistics["Nodes"] = ws.SuperGraph.Order()
			result.Statistics["Edges"] = ws.SuperGraph.Size()
		}
		c.JSON(200, result)
	})

	// WebSocket progress status
	backend.GET("ws-progress", func(c *gin.Context) {
		var upgrader = websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var laststatus string
		var lastpbr []ui.ProgressReport
		var skipcounter int

		for {
			currentstatus := ws.status.String()
			pbr := ui.GetProgressReport()
			slices.SortStableFunc(pbr, func(i, j ui.ProgressReport) int {
				return int(i.StartTime.Sub(j.StartTime))
			})

			if reflect.DeepEqual(lastpbr, pbr) && currentstatus == laststatus {
				time.Sleep(250 * time.Millisecond)
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
				Status:   currentstatus,
				Progress: pbr,
			}
			conn.SetWriteDeadline(time.Now().Add(time.Second * 15))
			err = conn.WriteJSON(output)
			if err != nil {
				ui.Error().Msgf("Error sending websocket message: %v", err)
				return
			}
			lastpbr = pbr
			laststatus = currentstatus
		}
	})

	// Polled progress status
	backend.GET("progress", func(c *gin.Context) {
		currentstatus := ws.status.String()
		pbr := ui.GetProgressReport()
		slices.SortStableFunc(pbr, func(i, j ui.ProgressReport) int {
			return int(i.StartTime.Sub(j.StartTime))
		})

		output := struct {
			Status   string              `json:"status"`
			Progress []ui.ProgressReport `json:"progressbars"`
		}{
			Status:   currentstatus,
			Progress: pbr,
		}
		c.JSON(200, output)
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

type APINodeDetails struct {
	ID                engine.NodeID       `json:"id"`
	Label             string              `json:"label"`
	DistinguishedName string              `json:"distinguishedname"`
	Attributes        map[string][]string `json:"attributes"`
	// CanPwn            map[string][]string `json:"can_pwn"`
	// PwnableBy         map[string][]string `json:"pwnable_by"`
}

type APIEdgeDetails struct {
	From  APINodeDetails                `json:"from"`
	To    APINodeDetails                `json:"to"`
	Edges map[string]engine.Probability `json:"edges"`
}

func apiNodeDetails(o *engine.Node, pretty bool) APINodeDetails {
	od := APINodeDetails{
		ID:                o.ID(),
		Label:             o.Label(),
		DistinguishedName: o.DN(),
		Attributes:        o.ValueMap(),
	}
	if pretty {
		for k, slice := range od.Attributes {
			for i := range slice {
				if !util.IsPrintableString(slice[i]) {
					slice[i] = util.Hexify(slice[i])
				}
				if len(slice[i]) > 256 {
					slice[i] = slice[i][:256] + " ..."
				}
			}
			sort.StringSlice(slice).Sort()
			od.Attributes[k] = slice
		}
	}
	return od
}

func apiEdgeDetails(g *engine.IndexedGraph, from, to *engine.Node) (APIEdgeDetails, bool) {
	eb, found := g.GetEdge(from, to)
	if !found {
		return APIEdgeDetails{}, false
	}

	ed := APIEdgeDetails{
		From:  apiNodeDetails(from, false),
		To:    apiNodeDetails(to, false),
		Edges: make(map[string]engine.Probability),
	}

	eb.Range(func(e engine.Edge) bool {
		ed.Edges[e.String()] = e.Probability(from, to, &eb)
		return true
	})
	return ed, true
}

func AddDataEndpoints(ws *WebService) {
	api := ws.API

	// Used for highlighting function
	api.GET("/search/get-ids", func(c *gin.Context) {
		querytext := c.Query("query")
		filter, err := query.ParseLDAPQueryStrict(querytext, ws.SuperGraph)
		if err != nil {
			if !strings.HasPrefix(querytext, "(") {
				querytext = "(*=" + querytext + ")"
				filter, err = query.ParseLDAPQueryStrict(querytext, ws.SuperGraph)
			}
		}
		if err != nil {
			c.AbortWithError(500, err)
			return
		}
		objects := ws.SuperGraph.Filter(filter.Evaluate)
		results := make([]string, 0, objects.Order())
		objects.Iterate(func(o *engine.Node) bool {
			results = append(results, fmt.Sprintf("n%v", o.ID()))
			return true
		})
		c.JSON(200, results)
	})

	// Returns JSON describing an object located by distinguishedName, sid or guid
	api.GET("details/:locateby/:id", ws.RequireData(Ready), func(c *gin.Context) {
		var o *engine.Node
		var found bool
		switch strings.ToLower(c.Param("locateby")) {
		case "id":
			index, err := strconv.ParseInt(c.Param("id"), 10, 64)
			if err != nil {
				c.String(500, "Error parsing index")
				return
			}
			o, found = ws.SuperGraph.IndexToNode(engine.NodeIndex(index))
		case "nodeid":
			id, err := strconv.ParseInt(c.Param("id"), 10, 64)
			if err != nil {
				c.String(500, "Error parsing ID")
				return
			}
			o, found = ws.SuperGraph.LookupNodeByID(engine.NodeID(id))
			// o, found = ws.SuperGraph.Find(engine.UniqueID, engine.NV(id))
		case "dn", "distinguishedname":
			o, found = ws.SuperGraph.Find(activedirectory.DistinguishedName, engine.NV(c.Param("id")))
		case "sid":
			sid, err := windowssecurity.ParseStringSID(c.Param("id"))
			if err != nil {
				c.String(500, err.Error())
				return
			}
			o, found = ws.SuperGraph.Find(activedirectory.ObjectSid, engine.NV(sid))
		case "guid":
			u, err := uuid.FromString(c.Param("id"))
			if err != nil {
				c.String(500, err.Error())
				return
			}
			o, found = ws.SuperGraph.Find(activedirectory.ObjectGUID, engine.NV(u))
		default:
			o, found = ws.SuperGraph.Find(engine.LookupAttribute(c.Param("locateby")), engine.NV(c.Param("id")))
		}
		if !found {
			c.AbortWithStatus(404)
			return
		}
		if c.Query("format") == "objectdump" {
			c.Writer.Write([]byte(o.StringACL(ws.SuperGraph)))
			return
		}

		c.JSON(200, apiNodeDetails(o, true))
	})
	api.GET("edges/:locateby/:ids", ws.RequireData(Ready), func(c *gin.Context) {
		var o *engine.Node
		var found bool

		ids := strings.Split(c.Param("ids"), ",")
		nodes := make([]*engine.Node, len(ids))

		switch strings.ToLower(c.Param("locateby")) {
		case "id":
			for i, id := range ids {
				thisId, err := strconv.ParseInt(id, 10, 64)
				if err != nil {
					c.String(500, "Error parsing ID")
					return
				}
				o, found = ws.SuperGraph.IndexToNode(engine.NodeIndex(thisId))
				if !found {
					c.AbortWithStatus(404)
					return
				}
				nodes[i] = o
			}
		case "nodeid":
			for i, id := range ids {
				thisId, err := strconv.ParseInt(id, 10, 64)
				if err != nil {
					c.String(500, "Error parsing ID")
					return
				}
				o, found = ws.SuperGraph.LookupNodeByID(engine.NodeID(thisId))
				if !found {
					c.AbortWithStatus(404)
					return
				}
				nodes[i] = o
			}
		case "dn", "distinguishedname":
			for i, id := range ids {
				o, found = ws.SuperGraph.Find(activedirectory.DistinguishedName, engine.NV(id))
				if !found {
					c.AbortWithStatus(404)
					return
				}
				nodes[i] = o
			}
		case "sid":
			for i, id := range ids {
				sid, err := windowssecurity.ParseStringSID(id)
				if err != nil {
					c.String(500, err.Error())
					return
				}
				o, found = ws.SuperGraph.Find(activedirectory.ObjectSid, engine.NV(sid))
				if !found {
					c.AbortWithStatus(404)
					return
				}
				nodes[i] = o
			}
		case "guid":
			for i, id := range ids {
				u, err := uuid.FromString(id)
				if err != nil {
					c.String(500, err.Error())
					return
				}
				o, found = ws.SuperGraph.Find(activedirectory.ObjectGUID, engine.NV(u))
				if !found {
					c.AbortWithStatus(404)
					return
				}
				nodes[i] = o
			}
		default:
			c.String(400, "Unknown lookup attribute %v", strings.ToLower(c.Param("locateby")))
			return
		}

		var lastnode *engine.Node
		result := make([]APIEdgeDetails, 0, len(nodes)-1)
		for _, o := range nodes {
			if lastnode != nil {
				ed, found := apiEdgeDetails(ws.SuperGraph, lastnode, o)
				if !found {
					c.String(404, "Edge between %v and %v not found", lastnode.ID(), o.ID())
					return
				}
				result = append(result, ed)
			}
			lastnode = o
		}

		c.JSON(200, result)
	})

	api.GET("tree", ws.RequireData(Ready), func(c *gin.Context) {
		idstr := c.Query("id")
		var children engine.NodeSlice
		if idstr == "#" {
			children = ws.SuperGraph.Root().Children()
		} else {
			id, err := strconv.ParseInt(idstr, 10, 64)
			if err != nil {
				c.String(400, "Problem converting id %v: %v", idstr, err)
				return
			}

			if parent, found := ws.SuperGraph.LookupNodeByID(engine.NodeID(id)); found {
				children = parent.Children()
			} else {
				c.String(404, "object not found")
				return
			}
		}
		type treeData struct {
			Label    string        `json:"text"`
			Type     string        `json:"type,omitempty"`
			ID       engine.NodeID `json:"id"`
			Children bool          `json:"children,omitempty"`
		}
		var results []treeData
		children.Iterate(func(object *engine.Node) bool {
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
		pb := ui.ProgressBar("Extracting words", int64(ws.SuperGraph.Order()))
		wordmap := make(map[string]struct{})
		ws.SuperGraph.Iterate(func(object *engine.Node) bool {
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
