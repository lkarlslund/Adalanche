package analyze

import (
	"encoding/json"
	"fmt"
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

func (ws *webservice) AddUIEndpoints(router gin.IRoutes) {
	// Lists available edges that Adalanche understands - this allows us to expand functionality
	// in the code, without touching the HTML
	router.GET("/filteroptions", func(c *gin.Context) {
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
			Methods     []filterinfo `json:"methods"`
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
	router.GET("/validatequery", func(c *gin.Context) {
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

	router.GET("/types", func(c *gin.Context) {
		c.JSON(200, typeInfos)
	})

	router.GET("/statistics", func(c *gin.Context) {
		var result struct {
			Adalanche  map[string]string `json:"adalanche"`
			Statistics map[string]int    `json:"statistics"`
		}
		result.Adalanche = make(map[string]string)
		result.Adalanche["shortversion"] = version.VersionStringShort()
		result.Adalanche["program"] = version.Program
		result.Adalanche["version"] = version.Version
		result.Adalanche["commit"] = version.Commit

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

	router.GET("/progress", func(c *gin.Context) {
		var upgrader = websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			pbr := ui.GetProgressReport()
			sort.Slice(pbr, func(i, j int) bool {
				return pbr[i].StartTime.Before(pbr[j].StartTime)
			})

			conn.SetWriteDeadline(time.Now().Add(time.Second * 15))
			err = conn.WriteJSON(pbr)
			if err != nil {
				return
			}

			time.Sleep(time.Second)
		}
	})

}

func (ws *webservice) AddPreferencesEndpoints(router gin.IRoutes) {
	// Saved preferences
	err := settings.Load()
	if err != nil {
		ui.Warn().Msgf("Problem loading preferences: %v", err)
	}

	router.GET("/preferences", func(c *gin.Context) {
		c.JSON(200, settings.All())
	})
	router.POST("/preferences", func(c *gin.Context) {
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

	router.GET("/preferences/:key", func(c *gin.Context) {
		key := c.Param("key")
		out, _ := json.Marshal(settings.Get(key))
		c.Writer.Write(out)
	})

	router.GET("/preferences/:key/:value", func(c *gin.Context) {
		key := c.Param("key")
		value := c.Param("value")
		settings.Set(key, value)
		settings.Save()
	})
}

func (ws *webservice) AddAnalysisEndpoints(router gin.IRoutes) {

	// Returns JSON descruibing an object located by distinguishedName, sid or guid
	router.GET("/details/:locateby/:id", func(c *gin.Context) {
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

	// Graph based query analysis - core functionality
	router.POST("/analyzegraph", func(c *gin.Context) {
		params := make(map[string]string)
		err := c.ShouldBindJSON(&params)
		// err := c.Request.ParseForm()
		if err != nil {
			c.String(500, err.Error())
			return
		}

		mode := params["mode"]
		if mode == "" {
			mode = "normal"
		}

		direction := engine.In
		if mode != "normal" {
			direction = engine.Out
		}

		prune, _ := util.ParseBool(params["prune"])

		startquerytext := params["query"]
		if startquerytext == "" {
			startquerytext = "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))"
		}

		middlequerytext := params["middlequery"]
		endquerytext := params["endquery"]

		maxdepth := -1
		if maxdepthval, err := strconv.Atoi(params["maxdepth"]); err == nil {
			maxdepth = maxdepthval
		}

		minprobability := 0
		if minprobabilityval, err := strconv.Atoi(params["minprobability"]); err == nil {
			minprobability = minprobabilityval
		}

		minaccprobability := 0
		if minaccprobabilityval, err := strconv.Atoi(params["minaccprobability"]); err == nil {
			minaccprobability = minaccprobabilityval
		}

		// Maximum number of outgoing connections from one object in analysis
		// If more are available you can right click the object and select EXPAND
		maxoutgoing := -1
		if maxoutgoingval, err := strconv.Atoi(params["maxoutgoing"]); err == nil {
			maxoutgoing = maxoutgoingval
		}

		alldetails, _ := util.ParseBool(params["alldetails"])
		// force, _ := util.ParseBool(vars["force"])

		backlinks, _ := strconv.Atoi(params["backlinks"])

		nodelimit, _ := strconv.Atoi(params["nodelimit"])

		dontexpandaueo, _ := util.ParseBool(params["dont-expand-au-eo"])

		opts := NewAnalyzeObjectsOptions()

		// tricky tricky - if we get a call with the expanddn set, then we handle things .... differently :-)
		if expanddn := params["expanddn"]; expanddn != "" {
			startquerytext = `(distinguishedName=` + expanddn + `)`
			maxoutgoing = 0
			maxdepth = 1
			nodelimit = 1000

			// tricky this is - if we're expanding a node it's suddenly the target, so we need to reverse the mode
			/*			if mode == "normal" {
							mode = "reverse"
						} else {
							mode = "normal"
						}*/
		}

		opts.StartFilter, err = query.ParseLDAPQueryStrict(startquerytext, ws.Objs)
		if err != nil {
			c.String(500, "Error parsing start query: %v", err)
			return
		}

		if middlequerytext != "" {
			opts.MiddleFilter, err = query.ParseLDAPQueryStrict(middlequerytext, ws.Objs)
			if err != nil {
				c.String(500, "Error parsing middle query: %v", err)
				return
			}
		}

		if endquerytext != "" {
			opts.EndFilter, err = query.ParseLDAPQueryStrict(endquerytext, ws.Objs)
			if err != nil {
				c.String(500, "Error parsing end query: %v", err)
				return
			}
		}

		// var methods engine.EdgeBitmap
		var edges_f, egdes_m, edges_l engine.EdgeBitmap
		var objecttypes_f, objecttypes_m, objecttypes_l []engine.ObjectType
		for potentialfilter := range c.Request.PostForm {
			if len(potentialfilter) < 7 {
				continue
			}
			if strings.HasPrefix(potentialfilter, "edge_") {
				prefix := potentialfilter[4 : len(potentialfilter)-2]
				suffix := potentialfilter[len(potentialfilter)-2:]
				edge := engine.LookupEdge(prefix)
				if edge == engine.NonExistingEdge {
					continue
				}
				switch suffix {
				case "_f":
					edges_f = edges_f.Set(edge)
				case "_m":
					egdes_m = egdes_m.Set(edge)
				case "_l":
					edges_l = edges_l.Set(edge)
				}
			} else if strings.HasPrefix(potentialfilter, "type_") {
				prefix := potentialfilter[5 : len(potentialfilter)-2]
				suffix := potentialfilter[len(potentialfilter)-2:]
				ot, found := engine.ObjectTypeLookup(prefix)
				if !found {
					continue
				}

				switch suffix {
				case "_f":
					objecttypes_f = append(objecttypes_f, ot)
				case "_m":
					objecttypes_m = append(objecttypes_m, ot)
				case "_l":
					objecttypes_l = append(objecttypes_l, ot)
				}
			}

		}

		// Are we using the new format FML? The just choose the old format methods for FML
		if edges_f.Count() == 0 && egdes_m.Count() == 0 && edges_l.Count() == 0 {
			// Spread the choices to FML
			edges_f = engine.AllEdgesBitmap
			egdes_m = engine.AllEdgesBitmap
			edges_l = engine.AllEdgesBitmap
		}

		opts.Objects = ws.Objs
		opts.MethodsF = edges_f
		opts.MethodsM = egdes_m
		opts.MethodsL = edges_l
		opts.ObjectTypesF = objecttypes_f
		opts.ObjectTypesM = objecttypes_m
		opts.ObjectTypesL = objecttypes_l
		opts.Direction = direction
		opts.MaxDepth = maxdepth
		opts.MaxOutgoingConnections = maxoutgoing
		opts.MinEdgeProbability = engine.Probability(minprobability)
		opts.MinAccumulatedProbability = engine.Probability(minaccprobability)
		opts.PruneIslands = prune
		opts.Backlinks = backlinks
		opts.NodeLimit = nodelimit
		opts.DontExpandAUEO = dontexpandaueo
		results := AnalyzeObjects(opts)

		for _, postprocessor := range PostProcessors {
			results.Graph = postprocessor(results.Graph)
		}
		var targets int

		var objecttypes [256]int

		for node := range results.Graph.Nodes() {
			if results.Graph.GetNodeData(node, "target") == true {
				targets++
				continue
			}
			objecttypes[node.Type()]++
		}

		resulttypes := make(map[string]int)
		for i := 0; i < 256; i++ {
			if objecttypes[i] > 0 {
				resulttypes[engine.ObjectType(i).String()] = objecttypes[i]
			}
		}

		cytograph, err := GenerateCytoscapeJS(results.Graph, alldetails)
		if err != nil {
			c.String(500, "Error generating cytoscape graph: %v", err)
			return
		}

		response := struct {
			Reversed bool `json:"reversed"`

			ResultTypes map[string]int `json:"resulttypes"`

			Targets int `json:"targets"`
			Total   int `json:"total"`
			Links   int `json:"links"`
			Removed int `json:"removed"`

			Elements *CytoElements `json:"elements"`
		}{
			Reversed: mode != "normal",

			ResultTypes: resulttypes,

			Targets: targets,
			Total:   results.Graph.Order(),
			Links:   results.Graph.Size(),
			Removed: results.Removed,

			Elements: &cytograph.Elements,
		}

		c.JSON(200, response)
	})

	router.GET("/query/objects/:query", func(c *gin.Context) {
		querystr := c.Param("query")

		rest, includequery, err := query.ParseLDAPQuery(querystr, ws.Objs)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		if rest != "" {
			if rest[0] != ',' {
				c.JSON(400, gin.H{"error": fmt.Sprintf("Error parsing ldap query: %v", err)})
				return
			}
		}

		objects := ws.Objs.Filter(func(o *engine.Object) bool {
			return includequery.Evaluate(o)
		})

		dns := make([]string, 0, objects.Len())

		objects.Iterate(func(o *engine.Object) bool {
			dns = append(dns, o.DN())
			return true
		})

		c.JSON(200, dns)
	})
	router.GET("/query/details/:query", func(c *gin.Context) {
		querystr := c.Param("query")

		rest, includequery, err := query.ParseLDAPQuery(querystr, ws.Objs)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		if rest != "" {
			if rest[0] != ',' {
				c.JSON(400, gin.H{"error": fmt.Sprintf("Error parsing ldap query: %v", err)})
				return
			}
		}

		objects := ws.Objs.Filter(func(o *engine.Object) bool {
			return includequery.Evaluate(o)
		})

		c.JSON(200, objects.AsSlice())
	})
	router.GET("/tree", func(c *gin.Context) {
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

	// Shutdown

	router.GET("/export-words", func(c *gin.Context) {
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

	// Ready status
	router.GET("/status", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": ws.status})
	})
	router.GET("/await/:status", func(c *gin.Context) {
		waitfor, err := WebServiceStatusString(c.Param("status"))
		if err != nil {
			c.Status(500)
			return
		}

		for ws.status != waitfor {
			time.Sleep(time.Millisecond * 10)
		}

		c.JSON(200, gin.H{"status": ws.status})
	})

	// Shutdown
	router.GET("/quit", func(c *gin.Context) {
		ws.quit <- true
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
