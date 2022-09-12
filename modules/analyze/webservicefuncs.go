package analyze

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/query"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func analysisfuncs(ws *webservice) {
	// Lists available pwnmethods that the system understands - this allows us to expand functionality
	// in the code, without toughting the HTML
	ws.Router.HandleFunc("/filteroptions", func(w http.ResponseWriter, r *http.Request) {
		type filterinfo struct {
			Name            string `json:"name"`
			Lookup          string `json:"lookup"`
			DefaultEnabledF bool   `json:"defaultenabled_f"`
			DefaultEnabledM bool   `json:"defaultenabled_m"`
			DefaultEnabledL bool   `json:"defaultenabled_l"`
			Description     string `json:"description"`
		}
		type returnobject struct {
			ObjectTypes []filterinfo `json:"objecttypes"`
			Methods     []filterinfo `json:"methods"`
		}
		var results returnobject

		for _, edge := range engine.AllEdgesSlice() {
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

		mj, _ := json.MarshalIndent(results, "", "  ")
		w.Write(mj)
	})
	// Checks a LDAP style query for input errors, and returns a hint to the user
	// It supports the include,exclude syntax specific to this program
	ws.Router.HandleFunc("/validatequery", func(w http.ResponseWriter, r *http.Request) {
		rest, _, err := query.ParseLDAPQuery(r.URL.Query().Get("query"), ws.Objs)
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
		if rest != "" {
			if rest[0] != ',' {
				w.WriteHeader(400) // bad request
				w.Write([]byte("Expecting comma as a seperator before exclude query"))
				return
			}
			if _, err := query.ParseLDAPQueryStrict(rest[1:], ws.Objs); err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
		}
		w.Write([]byte("ok"))
	})
	// Returns JSON descruibing an object located by distinguishedName, sid or guid
	ws.Router.HandleFunc("/details/{locateby}/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		var o *engine.Object
		var found bool
		switch strings.ToLower(vars["locateby"]) {
		case "id":
			id, err := strconv.Atoi(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = ws.Objs.FindByID(uint32(id))
		case "dn", "distinguishedname":
			o, found = ws.Objs.Find(activedirectory.DistinguishedName, engine.AttributeValueString(vars["id"]))
		case "sid":
			sid, err := windowssecurity.SIDFromString(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = ws.Objs.Find(activedirectory.ObjectSid, engine.AttributeValueSID(sid))
		case "guid":
			u, err := uuid.FromString(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = ws.Objs.Find(activedirectory.ObjectGUID, engine.AttributeValueGUID(u))
		}
		if !found {
			w.WriteHeader(404) // bad request
			w.Write([]byte("Object not found"))
			return
		}

		if r.FormValue("format") == "objectdump" {
			w.WriteHeader(200)
			w.Write([]byte(o.StringACL(ws.Objs)))
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

		for attr, values := range o.AttributeValueMap() {
			slice := values.StringSlice()
			sort.StringSlice(slice).Sort()
			od.Attributes[attr.String()] = slice
		}

		if r.FormValue("format") == "json" {
			w.WriteHeader(200)
			e := qjson.NewEncoder(w)
			e.SetIndent("", "  ")
			e.Encode(od.Attributes)
			return
		}

		e := qjson.NewEncoder(w)
		e.SetIndent("", "  ")
		err := e.Encode(od)
		// j, err := qjson.MarshalIndent(od)
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
		// w.WriteHeader(200)
	})
	// Graph based query analysis - core functionality
	ws.Router.HandleFunc("/cytograph.json", func(w http.ResponseWriter, r *http.Request) {
		vars := make(map[string]string)
		err := json.NewDecoder(r.Body).Decode(&vars)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Can't decode body: %v", err)
			return
		}

		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

		mode := vars["mode"]
		if mode == "" {
			mode = "normal"
		}
		reverse := (mode != "normal")

		prune, _ := util.ParseBool(vars["prune"])

		querystr := vars["query"]
		if querystr == "" {
			querystr = "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))"
		}

		maxdepth := 99
		if maxdepthval, err := strconv.Atoi(vars["maxdepth"]); err == nil {
			maxdepth = maxdepthval
		}

		minprobability := 0
		if minprobabilityval, err := strconv.Atoi(vars["minprobability"]); err == nil {
			minprobability = minprobabilityval
		}

		// Maximum number of outgoing connections from one object in analysis
		// If more are available you can right click the object and select EXPAND
		maxoutgoing := -1
		if maxoutgoingval, err := strconv.Atoi(vars["maxoutgoing"]); err == nil {
			maxoutgoing = maxoutgoingval
		}

		alldetails, _ := util.ParseBool(vars["alldetails"])
		force, _ := util.ParseBool(vars["force"])
		backlinks, _ := util.ParseBool(vars["backlinks"])

		var includeobjects *engine.Objects
		var excludeobjects *engine.Objects

		var excludequery query.Query

		// tricky tricky - if we get a call with the expanddn set, then we handle things .... differently :-)
		if expanddn := vars["expanddn"]; expanddn != "" {
			querystr = `(distinguishedName=` + expanddn + `)`
			maxoutgoing = 0
			maxdepth = 1
			force = true

			// tricky this is - if we're expanding a node it's suddenly the target, so we need to reverse the mode
			/*			if mode == "normal" {
							mode = "reverse"
						} else {
							mode = "normal"
						}*/
		}

		rest, includequery, err := query.ParseLDAPQuery(querystr, ws.Objs)
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
		if rest != "" {
			if rest[0] != ',' {
				w.WriteHeader(400) // bad request
				encoder.Encode(fmt.Sprintf("Error parsing ldap query: %v", err))
				return
			}
			if excludequery, err = query.ParseLDAPQueryStrict(rest[1:], ws.Objs); err != nil {
				w.WriteHeader(400) // bad request
				encoder.Encode(fmt.Sprintf("Error parsing ldap query: %v", err))
				return
			}
		}

		includeobjects = ws.Objs.Filter(func(o *engine.Object) bool {
			return includequery.Evaluate(o)
		})

		if excludequery != nil {
			excludeobjects = ws.Objs.Filter(func(o *engine.Object) bool {
				return excludequery.Evaluate(o)
			})
		}

		// var methods engine.EdgeBitmap
		var edges_f, egdes_m, edges_l engine.EdgeBitmap
		var objecttypes_f, objecttypes_m, objecttypes_l []engine.ObjectType
		for potentialfilter := range vars {
			if len(potentialfilter) < 7 {
				continue
			}
			if strings.HasPrefix(potentialfilter, "pwn_") {
				prefix := potentialfilter[4 : len(potentialfilter)-2]
				suffix := potentialfilter[len(potentialfilter)-2:]
				method := engine.E(prefix)
				if method == engine.NonExistingEdgeType {
					continue
				}
				switch suffix {
				case "_f":
					edges_f = edges_f.Set(method)
				case "_m":
					egdes_m = egdes_m.Set(method)
				case "_l":
					edges_l = edges_l.Set(method)
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

		var pg engine.Graph
		if mode == "sourcetarget" {
			if includeobjects.Len() == 0 || excludeobjects == nil || excludeobjects.Len() == 0 {
				fmt.Fprintf(w, "You must use two queries (source and target), seperated by commas. Each must return at least one object.")
			}

			// We dont support this yet, so merge all of them
			combinedmethods := edges_f.Merge(egdes_m).Merge(edges_l)

			for _, source := range includeobjects.Slice() {
				for _, target := range excludeobjects.Slice() {
					newpg := engine.AnalyzePaths(source, target, ws.Objs, combinedmethods, engine.Probability(minprobability), maxdepth)
					pg.Merge(newpg)
				}
			}
			// pg = engine.AnalyzePaths(includeobjects.Slice()[0], excludeobjects.Slice()[0], ws.Objs, combinedmethods, engine.Probability(minprobability), 1)
		} else {
			opts := engine.NewAnalyzeObjectsOptions()
			opts.IncludeObjects = includeobjects
			opts.ExcludeObjects = excludeobjects
			opts.MethodsF = edges_f
			opts.MethodsM = egdes_m
			opts.MethodsL = edges_l
			opts.ObjectTypesF = objecttypes_f
			opts.ObjectTypesM = objecttypes_m
			opts.ObjectTypesL = objecttypes_l
			opts.Reverse = reverse
			opts.MaxDepth = maxdepth
			opts.MaxOutgoingConnections = maxoutgoing
			opts.MinProbability = engine.Probability(minprobability)
			opts.PruneIslands = prune
			opts.Backlinks = backlinks
			pg = engine.AnalyzeObjects(opts)
		}

		for _, postprocessor := range engine.PostProcessors {
			pg = postprocessor(pg)
		}
		/*
			clusters := pg.SCC()
			for i, cluster := range clusters {
				if len(cluster) == 1 {
					continue
				}
				ui.Debug().Msgf("Cluster %v has %v members:", i, len(cluster))
				for _, member := range cluster {
					ui.Debug().Msgf("%v", member.DN())
				}
			}
		*/
		var targets int

		var objecttypes [256]int

		for _, node := range pg.Nodes {
			if node.Target {
				targets++
				continue
			}
			objecttypes[node.Object.Type()]++
		}

		resulttypes := make(map[string]int)
		for i := 0; i < 256; i++ {
			if objecttypes[i] > 0 {
				resulttypes[engine.ObjectType(i).String()] = objecttypes[i]
			}
		}

		if len(pg.Nodes) > 1000 && !force {
			w.WriteHeader(413) // too big payload response
			errormsg := fmt.Sprintf("Too much data :-( %v target nodes can ", targets)
			if mode != "normal" || strings.HasPrefix(mode, "sourcetarget") {
				errormsg += "can pwn"
			} else {
				errormsg += "be can pwned by"
			}
			errormsg += fmt.Sprintf(" %v total nodes<br>", len(pg.Nodes)-targets)
			var notfirst bool
			for objecttype, count := range resulttypes {
				if notfirst {
					errormsg += ", "
				}
				errormsg += fmt.Sprintf("%v %v", count, objecttype)
				notfirst = true
			}

			// FIUXME - POST AS JSON BROKE THIS
			// errormsg += fmt.Sprintf(". Use force option to potentially crash your browser or <a href=\"%v\">download a GML file.</a>", "/export-graph?format=xgmml&"+r.URL.RawQuery)

			fmt.Fprintf(w, errormsg)
			return
		}

		cytograph, err := GenerateCytoscapeJS(pg, alldetails)
		if err != nil {
			w.WriteHeader(500)
			encoder.Encode("Error during graph creation")
			return
		}

		response := struct {
			Reversed bool `json:"reversed"`

			ResultTypes map[string]int `json:"resulttypes"`

			Targets int `json:"targets"`
			Total   int `json:"total"`
			Links   int `json:"links"`

			Elements *CytoElements `json:"elements"`
		}{
			Reversed: mode != "normal",

			ResultTypes: resulttypes,

			Targets: targets,
			Total:   len(pg.Nodes),
			Links:   len(pg.Connections),

			Elements: &cytograph.Elements,
		}

		err = encoder.Encode(response)
		if err != nil {
			w.WriteHeader(500)
			encoder.Encode("Error during JSON encoding")
		}
	})

	ws.Router.HandleFunc("/export-graph", func(w http.ResponseWriter, r *http.Request) {
		uq := r.URL.Query()

		format := uq.Get("format")
		if format == "" {
			format = "xgmml"
		}

		mode := uq.Get("mode")
		if mode == "" {
			mode = "normal"
		}
		reverse := (mode != "normal")

		querystr := uq.Get("query")
		if querystr == "" {
			querystr = "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))"
		}

		maxdepth := 99
		if maxdepthval, err := strconv.Atoi(uq.Get("maxdepth")); err == nil {
			maxdepth = maxdepthval
		}

		maxoutgoing := -1
		if maxoutgoingval, err := strconv.Atoi(uq.Get("maxotgoing")); err == nil {
			maxoutgoing = maxoutgoingval
		}

		alldetails, err := util.ParseBool(uq.Get("alldetails"))
		if err != nil {
			alldetails = true
		}

		var includeobjects *engine.Objects
		var excludeobjects *engine.Objects

		var excludequery query.Query

		rest, includequery, err := query.ParseLDAPQuery(r.URL.Query().Get("query"), ws.Objs)
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
		if rest != "" {
			if rest[0] != ',' {
				w.WriteHeader(400) // bad request
				fmt.Fprintf(w, "Error parsing ldap query: %v", err)
				return
			}
			if excludequery, err = query.ParseLDAPQueryStrict(rest[1:], ws.Objs); err != nil {
				w.WriteHeader(400) // bad request
				fmt.Fprintf(w, "Error parsing ldap query: %v", err)
				return
			}
		}

		includeobjects = ws.Objs.Filter(func(o *engine.Object) bool {
			// Domain Admins and Enterprise Admins groups
			return includequery.Evaluate(o)
		})

		if excludequery != nil {
			excludeobjects = ws.Objs.Filter(func(o *engine.Object) bool {
				// Domain Admins and Enterprise Admins groups
				return excludequery.Evaluate(o)
			})
		}

		var selectededges []engine.Edge
		for potentialedge, values := range uq {
			if edge := engine.E(potentialedge); edge != engine.NonExistingEdgeType {
				enabled, _ := util.ParseBool(values[0])
				if len(values) == 1 && enabled {
					selectededges = append(selectededges, edge)
				}
			}
		}
		// If everything is deselected, select everything
		if len(selectededges) == 0 {
			selectededges = engine.AllEdgesSlice()
		}

		var methods engine.EdgeBitmap
		for _, m := range selectededges {
			methods = methods.Set(m)
		}

		opts := engine.NewAnalyzeObjectsOptions()
		opts.IncludeObjects = includeobjects
		opts.ExcludeObjects = excludeobjects
		opts.MethodsF = methods
		opts.MethodsM = methods
		opts.MethodsL = methods
		opts.Reverse = reverse
		opts.MaxDepth = maxdepth
		opts.MaxOutgoingConnections = maxoutgoing
		opts.MinProbability = 0

		pg := engine.AnalyzeObjects(opts)

		// Make browser download this
		filename := "analysis-" + time.Now().Format(time.RFC3339)

		switch format {
		case "gml":
			filename += ".gml"
		case "xgmml":
			filename += ".xgmml"
		}

		w.Header().Set("Content-Disposition", "attachment; filename="+filename)

		switch format {
		case "gml":
			// Lets go
			w.Write([]byte("graph\n[\n"))

			for id, node := range pg.Nodes {
				fmt.Fprintf(w,
					`  node
  [
    id %v
    label %v
	distinguishedName %v
`, id, node.Label(), node.DN())

				if alldetails {
					for attribute, values := range node.AttributeValueMap() {
						valuesjoined := strings.Join(values.StringSlice(), ", ")
						if util.IsASCII(valuesjoined) {
							fmt.Fprintf(w, "  %v %v\n", attribute, valuesjoined)
						}
					}
				}
				fmt.Fprintf(w, "  ]\n")
			}

			for _, pwn := range pg.Connections {
				fmt.Fprintf(w,
					`  edge
  [
    source %v
    target %v
	label "%v"
  ]
`, pwn.Source.ID(), pwn.Target.ID(), methods.JoinedString())
			}

			w.Write([]byte("]\n"))

		case "xgmml":
			graph := NewXGMMLGraph()

			for _, node := range pg.Nodes {
				object := node.Object
				xmlnode := XGMMLNode{
					Id:    object.ID(),
					Label: object.Label(),
				}

				if alldetails {
					for attribute, values := range object.AttributeValueMap() {
						if values != nil {
							valuesjoined := strings.Join(values.StringSlice(), ", ")
							if util.IsASCII(valuesjoined) {
								xmlnode.Attributes = append(xmlnode.Attributes, XGMMLAttribute{
									Name:  attribute.String(),
									Value: valuesjoined,
								})
							}
						}
					}
				}
				graph.Nodes = append(graph.Nodes, xmlnode)
			}

			for _, pwn := range pg.Connections {
				graph.Edges = append(graph.Edges, XGMMLEdge{
					Source: pwn.Source.ID(),
					Target: pwn.Target.ID(),
					Label:  pwn.JoinedString(),
				})
			}
			fmt.Fprint(w, xml.Header)
			xe := xml.NewEncoder(w)
			xe.Indent("", "  ")
			xe.Encode(graph)
		}
	})

	ws.Router.HandleFunc("/query/objects/{query}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		querystr := vars["query"]
		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

		rest, includequery, err := query.ParseLDAPQuery(querystr, ws.Objs)
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
		if rest != "" {
			if rest[0] != ',' {
				w.WriteHeader(400) // bad request
				encoder.Encode(gin.H{"error": fmt.Sprintf("Error parsing ldap query: %v", err)})
				return
			}
		}

		objects := ws.Objs.Filter(func(o *engine.Object) bool {
			return includequery.Evaluate(o)
		})

		dns := make([]string, len(objects.Slice()))

		for i, o := range objects.Slice() {
			dns[i] = o.DN()
		}

		err = encoder.Encode(dns)
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
	})
	ws.Router.HandleFunc("/query/details/{query}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		querystr := vars["query"]
		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

		rest, includequery, err := query.ParseLDAPQuery(querystr, ws.Objs)
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
		if rest != "" {
			if rest[0] != ',' {
				w.WriteHeader(400) // bad request
				encoder.Encode(gin.H{"error": fmt.Sprintf("Error parsing ldap query: %v", err)})
				return
			}
		}

		objects := ws.Objs.Filter(func(o *engine.Object) bool {
			return includequery.Evaluate(o)
		})

		err = encoder.Encode(objects.Slice())
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(200)
	})
	ws.Router.HandleFunc("/accountinfo.json", func(w http.ResponseWriter, r *http.Request) {
		type info struct {
			DN            string    `json:"dn"`
			PwdAge        time.Time `json:"lastpwdchange,omitempty"`
			CreatedAge    time.Time `json:"created,omitempty"`
			ChangedAge    time.Time `json:"lastchange,omitempty"`
			LoginAge      time.Time `json:"lastlogin,omitempty"`
			Expires       time.Time `json:"expires,omitempty"`
			Type          string    `json:"type"`
			Unconstrained bool      `json:"unconstrained,omitempty"`
			Workstation   bool      `json:"workstation,omitempty"`
			Server        bool      `json:"server,omitempty"`
			Enabled       bool      `json:"enabled,omitempty"`
			CantChangePwd bool      `json:"cantchangepwd,omitempty"`
			NoExpirePwd   bool      `json:"noexpirepwd,omitempty"`
			NoRequirePwd  bool      `json:"norequirepwd,omitempty"`
			HasLAPS       bool      `json:"haslaps,omitempty"`
		}
		var result []info
		for _, object := range ws.Objs.Slice() {
			if object.Type() == engine.ObjectTypeUser &&
				object.OneAttrString(engine.MetaWorkstation) != "1" &&
				object.OneAttrString(engine.MetaServer) != "1" &&
				object.OneAttrString(engine.MetaAccountDisabled) != "1" {
				lastlogin, _ := object.AttrTimestamp(activedirectory.LastLogon)
				lastlogints, _ := object.AttrTimestamp(activedirectory.LastLogonTimestamp)
				last, _ := object.AttrTimestamp(activedirectory.PwdLastSet)

				expires, _ := object.AttrTimestamp(activedirectory.AccountExpires)
				created, _ := object.AttrTimestamp(activedirectory.WhenCreated)
				changed, _ := object.AttrTimestamp(activedirectory.WhenChanged)

				// ui.Debug().Msgf("%v last pwd %v / login %v / logints %v / expires %v / changed %v / created %v", object.DN(), last, lastlogin, lastlogints, expires, changed, created)

				if lastlogin.After(lastlogints) {
					lastlogints = lastlogin
				}

				// // var loginage int

				// if !lastlogints.IsZero() {
				// 	loginage = int(time.Since(lastlogints).Hours()) / 24
				// }

				i := info{
					DN:         object.DN(),
					PwdAge:     last,
					ChangedAge: changed,
					CreatedAge: created,
					LoginAge:   lastlogints,
					Expires:    expires,
					Type:       object.Type().String(),

					Unconstrained: object.OneAttrString(engine.MetaUnconstrainedDelegation) == "1",
					Workstation:   object.OneAttrString(engine.MetaWorkstation) == "1",
					Server:        object.OneAttrString(engine.MetaServer) == "1",
					Enabled:       object.OneAttrString(engine.MetaAccountDisabled) != "1",
					CantChangePwd: object.OneAttrString(engine.MetaPasswordCantChange) == "1",
					NoExpirePwd:   object.OneAttrString(engine.MetaPasswordNoExpire) == "1",
					NoRequirePwd:  object.OneAttrString(engine.MetaPasswordNotRequired) == "1",
					HasLAPS:       object.OneAttrString(engine.MetaLAPSInstalled) == "1",
				}

				// if uac&UAC_NOT_DELEGATED != 0 {
				// 	ui.Debug().Msgf("%v has can't be used as delegation", object.DN())
				// }

				result = append(result, i)
			}
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(data)
	})

	ws.Router.Path("/tree").Queries("id", "{id}").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		idstr := vars["id"]
		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

		var children []*engine.Object
		if idstr == "#" {
			children = ws.Objs.Root().Children()
		} else {
			id, err := strconv.Atoi(idstr)
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}

			if parent, found := ws.Objs.FindByID(uint32(id)); found {
				children = parent.Children()
			} else {
				w.WriteHeader(404) // not found
				w.Write([]byte("object not found"))
				return
			}
		}

		type treeData struct {
			Label    string `json:"text"`
			Type     string `json:"type,omitempty"`
			ID       uint32 `json:"id"`
			Children bool   `json:"children,omitempty"`
		}

		var results []treeData
		for _, object := range children {
			results = append(results, treeData{
				ID:       object.ID(),
				Label:    object.Label(),
				Type:     object.Type().String(),
				Children: len(object.Children()) > 0,
			})
		}

		err := encoder.Encode(results)
		if err != nil {
			w.WriteHeader(400) // bad request
			w.Write([]byte(err.Error()))
			return
		}
	})

	ws.Router.HandleFunc("/statistics", func(w http.ResponseWriter, r *http.Request) {
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

		for objecttype, count := range ws.Objs.Statistics() {
			if objecttype == 0 {
				continue // skip the dummy one
			}
			if count == 0 {
				continue
			}
			result.Statistics[engine.ObjectType(objecttype).String()] += count
		}

		var pwnlinks int
		for _, object := range ws.Objs.Slice() {
			pwnlinks += object.EdgeCount(engine.Out)
		}
		result.Statistics["Total"] = len(ws.Objs.Slice())
		result.Statistics["PwnConnections"] = pwnlinks

		data, _ := json.MarshalIndent(result, "", "  ")
		w.Write(data)
	})

	// Saved preferences
	var prefs Prefs
	err := prefs.Load()
	if err != nil {
		ui.Warn().Msgf("Problem loading preferences: %v", err)
	}

	ws.Router.HandleFunc("/preferences", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(prefs.data)
		case "POST":
			newprefs := make(map[string]interface{})
			err := json.NewDecoder(r.Body).Decode(&newprefs)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprintf(w, "Can't decode body: %v", err)
				return
			}
			for key, value := range newprefs {
				prefs.Set(key, value)
			}
			prefs.Save()
		}
	})
	ws.Router.HandleFunc("/preferences/{key}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		key := vars["key"]
		out, _ := json.Marshal(prefs.Get(key))
		w.Write(out)
	})

	// Shutdown
	ws.Router.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) {
		ws.quit <- true
	})

}
