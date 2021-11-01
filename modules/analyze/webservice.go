package analyze

import (
	"embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/absfs/gofs"
	"github.com/absfs/osfs"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ldapquery"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

//go:embed html/*
var embeddedassets embed.FS

var (
	qjson = jsoniter.ConfigCompatibleWithStandardLibrary
)

type FSPrefix struct {
	Prefix string
	FS     fs.FS
}

func (f FSPrefix) Open(filename string) (fs.File, error) {
	return f.FS.Open(path.Join(f.Prefix, filename))
}

func webservice(bind string, quit chan bool, objs *engine.Objects) (*http.Server, error) {
	router := mux.NewRouter()
	srv := http.Server{
		Addr:    bind,
		Handler: router,
	}
	// Lists available pwnmethods that the system understands - this allows us to expand functionality
	// in the code, without toughting the HTML
	router.HandleFunc("/filteroptions", func(w http.ResponseWriter, r *http.Request) {
		type filterinfo struct {
			Name            string `json:"name"`
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

		for _, method := range engine.AllPwnMethodsSlice() {
			results.Methods = append(results.Methods, filterinfo{
				Name:            method.String(),
				DefaultEnabledF: !strings.HasPrefix(method.String(), "Create") && !strings.HasPrefix(method.String(), "Delete") && !strings.HasPrefix(method.String(), "Inherits"),
				DefaultEnabledM: !strings.HasPrefix(method.String(), "Create") && !strings.HasPrefix(method.String(), "Delete") && !strings.HasPrefix(method.String(), "Inherits"),
				DefaultEnabledL: !strings.HasPrefix(method.String(), "Create") && !strings.HasPrefix(method.String(), "Delete") && !strings.HasPrefix(method.String(), "Inherits"),
			})
		}

		for _, objecttype := range engine.ObjectTypeValues() {
			results.ObjectTypes = append(results.ObjectTypes, filterinfo{
				Name:            objecttype.String(),
				DefaultEnabledF: true,
				DefaultEnabledM: true,
				DefaultEnabledL: true,
			})
		}

		mj, _ := json.MarshalIndent(results, "", "  ")
		w.Write(mj)
	})
	// Checks a LDAP style query for input errors, and returns a hint to the user
	// It supports the include,exclude syntax specific to this program
	router.HandleFunc("/validatequery", func(w http.ResponseWriter, r *http.Request) {
		rest, _, err := ldapquery.ParseQuery(r.URL.Query().Get("query"), objs)
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
			if _, err := ldapquery.ParseQueryStrict(rest[1:], objs); err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
		}
		w.Write([]byte("ok"))
	})
	// Returns JSON descruibing an object located by distinguishedName, sid or guid
	router.HandleFunc("/details/{locateby}/{id}", func(w http.ResponseWriter, r *http.Request) {
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
			o, found = objs.FindByID(uint32(id))
		case "dn", "distinguishedname":
			o, found = objs.Find(engine.DistinguishedName, engine.AttributeValueString(vars["id"]))
		case "sid":
			sid, err := windowssecurity.SIDFromString(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = objs.Find(engine.ObjectSid, engine.AttributeValueSID(sid))
		case "guid":
			u, err := uuid.FromString(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = objs.Find(engine.ObjectGUID, engine.AttributeValueGUID(u))
		}
		if !found {
			w.WriteHeader(404) // bad request
			w.Write([]byte("Object not found"))
			return
		}

		if r.FormValue("format") == "objectdump" {
			w.WriteHeader(200)
			w.Write([]byte(o.String(objs)))
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

		for attr, values := range o.AttributeValueMap {
			od.Attributes[attr.String()] = values.StringSlice()
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
	router.HandleFunc("/cytograph.json", func(w http.ResponseWriter, r *http.Request) {
		vars := make(map[string]string)
		err := json.NewDecoder(r.Body).Decode(&vars)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Can't decode body: %v", err)
			return
		}

		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

		// anonymize, _ := util.ParseBool(vars["anonymize"])

		mode := vars["mode"]
		if mode == "" {
			mode = "normal"
		}
		reverse := (mode != "normal")

		prune, _ := util.ParseBool(vars["prune"])

		query := vars["query"]
		if query == "" {
			query = "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))"
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
		maxoutgoing := 500
		if maxoutgoingval, err := strconv.Atoi(vars["maxoutgoing"]); err == nil {
			maxoutgoing = maxoutgoingval
		}

		alldetails, _ := util.ParseBool(vars["alldetails"])
		force, _ := util.ParseBool(vars["force"])
		backlinks, _ := util.ParseBool(vars["backlinks"])

		var includeobjects *engine.Objects
		var excludeobjects *engine.Objects

		var excludequery ldapquery.Query

		// tricky tricky - if we get a call with the expanddn set, then we handle things .... differently :-)
		if expanddn := vars["expanddn"]; expanddn != "" {
			query = `(distinguishedName=` + expanddn + `)`
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

		rest, includequery, err := ldapquery.ParseQuery(query, objs)
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
			if excludequery, err = ldapquery.ParseQueryStrict(rest[1:], objs); err != nil {
				w.WriteHeader(400) // bad request
				encoder.Encode(fmt.Sprintf("Error parsing ldap query: %v", err))
				return
			}
		}

		includeobjects = objs.Filter(func(o *engine.Object) bool {
			// Domain Admins and Enterprise Admins groups
			return includequery.Evaluate(o)
		})

		if excludequery != nil {
			excludeobjects = objs.Filter(func(o *engine.Object) bool {
				// Domain Admins and Enterprise Admins groups
				return excludequery.Evaluate(o)
			})
		}

		// var methods engine.PwnMethodBitmap
		var methods_f, methods_m, methods_l engine.PwnMethodBitmap
		var objecttypes_f, objecttypes_m, objecttypes_l []engine.ObjectType
		for potentialfilter := range vars {
			if len(potentialfilter) < 7 {
				continue
			}
			if strings.HasPrefix(potentialfilter, "pwn_") {
				prefix := potentialfilter[4 : len(potentialfilter)-2]
				suffix := potentialfilter[len(potentialfilter)-2:]
				method := engine.P(prefix)
				if method == engine.NonExistingPwnMethod {
					continue
				}
				switch suffix {
				case "_f":
					methods_f = methods_f.Set(method)
				case "_m":
					methods_m = methods_m.Set(method)
				case "_l":
					methods_l = methods_l.Set(method)
				}
			} else if strings.HasPrefix(potentialfilter, "type_") {
				prefix := potentialfilter[5 : len(potentialfilter)-2]
				suffix := potentialfilter[len(potentialfilter)-2:]
				ot, found := engine.ObjectTypeString(prefix)
				if found != nil {
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
		if methods_f.Count() == 0 && methods_m.Count() == 0 && methods_l.Count() == 0 {
			// Spread the choices to FML
			methods_f = engine.AllPwnMethods
			methods_m = engine.AllPwnMethods
			methods_l = engine.AllPwnMethods
		}

		var pg engine.PwnGraph
		if mode == "sourcetarget" {
			if len(includeobjects.Slice()) == 0 || excludeobjects == nil || len(excludeobjects.Slice()) == 0 {
				fmt.Fprintf(w, "You must use two queries (source and target), seperated by commas. Each must return at least one object.")
			}

			// We dont support this yet, so merge all of them
			combinedmethods := methods_f.Merge(methods_m).Merge(methods_l)

			pg = engine.AnalyzePaths(includeobjects.Slice()[0], excludeobjects.Slice()[0], objs, combinedmethods, engine.Probability(minprobability), 1)
		} else {
			opts := engine.NewAnalyzeObjectsOptions()
			opts.IncludeObjects = includeobjects
			opts.ExcludeObjects = excludeobjects
			opts.MethodsF = methods_f
			opts.MethodsM = methods_m
			opts.MethodsL = methods_l
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

		clusters := pg.SCC()
		for i, cluster := range clusters {
			if len(cluster) == 1 {
				continue
			}
			log.Debug().Msgf("Cluster %v has %v members:", i, len(cluster))
			for _, member := range cluster {
				log.Debug().Msgf("%v", member.DN())
			}
		}

		var targets int

		var objecttypes [engine.OBJECTTYPEMAX]int

		for _, node := range pg.Nodes {
			if node.Target {
				targets++
				continue
			}
			objecttypes[node.Object.Type()]++
		}

		resulttypes := make(map[string]int)
		for i := 0; i < engine.OBJECTTYPEMAX; i++ {
			if objecttypes[i] > 0 {
				resulttypes[engine.ObjectType(i).String()] = objecttypes[i]
			}
		}

		if len(pg.Nodes) > 1000 && !force {
			w.WriteHeader(413) // too big payload response
			errormsg := fmt.Sprintf("Too much data :-( %v targets can ", targets)
			if mode != "normal" || strings.HasPrefix(mode, "sourcetarget") {
				errormsg += "can pwn"
			} else {
				errormsg += "be can pwned by"
			}
			var notfirst bool
			for objecttype, count := range resulttypes {
				if notfirst {
					errormsg += ","
				}
				errormsg += fmt.Sprintf(" %v %v", count, objecttype)
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

	router.HandleFunc("/export-graph", func(w http.ResponseWriter, r *http.Request) {
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

		query := uq.Get("query")
		if query == "" {
			query = "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))"
		}

		maxdepth := 99
		if maxdepthval, err := strconv.Atoi(uq.Get("maxdepth")); err == nil {
			maxdepth = maxdepthval
		}

		maxoutgoing := 0
		if maxoutgoingval, err := strconv.Atoi(uq.Get("maxotgoing")); err == nil {
			maxoutgoing = maxoutgoingval
		}

		alldetails, err := util.ParseBool(uq.Get("alldetails"))
		if err != nil {
			alldetails = true
		}

		var includeobjects *engine.Objects
		var excludeobjects *engine.Objects

		var excludequery ldapquery.Query

		rest, includequery, err := ldapquery.ParseQuery(r.URL.Query().Get("query"), objs)
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
			if excludequery, err = ldapquery.ParseQueryStrict(rest[1:], objs); err != nil {
				w.WriteHeader(400) // bad request
				fmt.Fprintf(w, "Error parsing ldap query: %v", err)
				return
			}
		}

		includeobjects = objs.Filter(func(o *engine.Object) bool {
			// Domain Admins and Enterprise Admins groups
			return includequery.Evaluate(o)
		})

		if excludequery != nil {
			excludeobjects = objs.Filter(func(o *engine.Object) bool {
				// Domain Admins and Enterprise Admins groups
				return excludequery.Evaluate(o)
			})
		}

		var selectedmethods []engine.PwnMethod
		for potentialmethod, values := range uq {
			if method := engine.P(potentialmethod); method != engine.NonExistingPwnMethod {
				enabled, _ := util.ParseBool(values[0])
				if len(values) == 1 && enabled {
					selectedmethods = append(selectedmethods, method)
				}
			}
		}
		// If everything is deselected, select everything
		if len(selectedmethods) == 0 {
			selectedmethods = engine.AllPwnMethodsSlice()
		}

		var methods engine.PwnMethodBitmap
		for _, m := range selectedmethods {
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
					for attribute, values := range node.AttributeValueMap {
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
					for attribute, values := range object.AttributeValueMap {
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

	router.HandleFunc("/query/objects/{query}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		query := vars["query"]
		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

		rest, includequery, err := ldapquery.ParseQuery(query, objs)
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

		objects := objs.Filter(func(o *engine.Object) bool {
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
	router.HandleFunc("/query/details/{query}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		query := vars["query"]
		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

		rest, includequery, err := ldapquery.ParseQuery(query, objs)
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

		objects := objs.Filter(func(o *engine.Object) bool {
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
	router.HandleFunc("/accountinfo.json", func(w http.ResponseWriter, r *http.Request) {
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
		for _, object := range objs.Slice() {
			if object.Type() == engine.ObjectTypeUser &&
				object.OneAttrString(engine.MetaWorkstation) != "1" &&
				object.OneAttrString(engine.MetaServer) != "1" &&
				object.OneAttrString(engine.MetaAccountDisabled) != "1" {
				lastlogin, _ := object.AttrTimestamp(engine.LastLogon)
				lastlogints, _ := object.AttrTimestamp(engine.LastLogonTimestamp)
				last, _ := object.AttrTimestamp(engine.PwdLastSet)

				expires, _ := object.AttrTimestamp(engine.AccountExpires)
				created, _ := object.AttrTimestamp(engine.WhenCreated)
				changed, _ := object.AttrTimestamp(engine.WhenChanged)

				// log.Debug().Msgf("%v last pwd %v / login %v / logints %v / expires %v / changed %v / created %v", object.DN(), last, lastlogin, lastlogints, expires, changed, created)

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
				// 	log.Debug().Msgf("%v has can't be used as delegation", object.DN())
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

	router.Path("/tree").Queries("id", "{id}").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		idstr := vars["id"]
		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

		var children []*engine.Object
		if idstr == "#" {
			children = objs.Root().Children()
		} else {
			id, err := strconv.Atoi(idstr)
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}

			if parent, found := objs.FindByID(uint32(id)); found {
				children = parent.Children()
			} else {
				w.WriteHeader(404) // not found
				w.Write([]byte("object not found"))
				return
			}
		}

		type treeData struct {
			ID       uint32 `json:"id"`
			Label    string `json:"text"`
			Type     string `json:"type,omitempty"`
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

	router.HandleFunc("/statistics", func(w http.ResponseWriter, r *http.Request) {
		var result struct {
			Adalanche  map[string]string `json:"adalanche"`
			Statistics map[string]int    `json:"statistics"`
		}
		result.Adalanche = make(map[string]string)
		result.Adalanche["shortversion"] = version.VersionStringShort()[len(version.Program)+1:]
		result.Adalanche["program"] = version.Program
		result.Adalanche["version"] = version.Version
		result.Adalanche["commit"] = version.Commit
		result.Adalanche["builddate"] = version.Builddate

		result.Statistics = make(map[string]int)

		for objecttype, count := range objs.Statistics() {
			if objecttype == 0 {
				continue // skip the dummy one
			}
			result.Statistics[engine.ObjectType(objecttype).String()] += count
		}

		var pwnlinks int
		for _, object := range objs.Slice() {
			pwnlinks += len(object.CanPwn)
		}
		result.Statistics["Total"] = len(objs.Slice())
		result.Statistics["PwnConnections"] = pwnlinks

		data, _ := json.MarshalIndent(result, "", "  ")
		w.Write(data)
	})

	// Saved preferences
	var prefs Prefs
	err := prefs.Load()
	if err != nil {
		log.Warn().Msgf("Problem loading preferences: %v", err)
	}

	router.HandleFunc("/preferences", func(w http.ResponseWriter, r *http.Request) {
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
	router.HandleFunc("/preferences/{key}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		key := vars["key"]
		out, _ := json.Marshal(prefs.Get(key))
		w.Write(out)
	})

	// Shutdown
	router.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) {
		quit <- true
	})

	// Serve embedded static files, or from html folder if it exists
	if *localhtml == "" {
		router.PathPrefix("/").Handler(http.FileServer(http.FS(FSPrefix{
			Prefix: "html",
			FS:     embeddedassets,
		})))
	} else {
		// Override embedded HTML if asked to
		if stat, err := os.Stat(*localhtml); err == nil && stat.IsDir() {
			// Use local files if they exist
			log.Info().Msgf("Switching from embedded HTML to local folder %v", *localhtml)
			if osf, err := osfs.NewFS(); err == nil {
				err = osf.Chdir(*localhtml) // Move up one folder, so we have html/ below us
				if err != nil {
					return nil, errors.Wrap(err, "")
				}
				assets, err := gofs.NewFs(osf)
				if err != nil {
					return nil, errors.Wrap(err, "")
				}
				router.PathPrefix("/").Handler(http.FileServer(http.FS(FSPrefix{
					// Prefix: "html",
					FS: assets,
				})))
			}
		} else {
			log.Warn().Msgf("Not switching from embedded HTML to local folder %v, failure: %v", *localhtml, err)
		}
	}

	log.Info().Msgf("Listening - navigate to %v ... (ctrl-c or similar to quit)", bind)

	return &srv, nil
}
