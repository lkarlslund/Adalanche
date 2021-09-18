package main

import (
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
	"github.com/rs/zerolog/log"
)

type FSPrefix struct {
	Prefix string
	FS     fs.FS
}

func (f FSPrefix) Open(filename string) (fs.File, error) {
	return f.FS.Open(path.Join(f.Prefix, filename))
}

func webservice(bind string, quit chan bool) http.Server {
	router := mux.NewRouter()
	srv := http.Server{
		Addr:    bind,
		Handler: router,
	}
	// Lists available pwnmethods that the system understands - this allows us to expand functionality
	// in the code, without toughting the HTML
	router.HandleFunc("/pwnmethods", func(w http.ResponseWriter, r *http.Request) {
		type methodinfo struct {
			Name           string `json:"name"`
			DefaultEnabled bool   `json:"defaultenabled"`
			Description    string `json:"description"`
		}
		var methods []methodinfo

		for _, method := range PwnMethodValues() {
			methods = append(methods, methodinfo{
				Name:           method.String(),
				DefaultEnabled: !strings.HasPrefix(method.String(), "Create") && !strings.HasPrefix(method.String(), "Delete") && !strings.HasPrefix(method.String(), "Inherits"),
				// Description:    method.Description(),
			})
		}

		mj, _ := json.MarshalIndent(methods, "", "  ")
		w.Write(mj)
	})
	// Checks a LDAP style query for input errors, and returns a hint to the user
	// It supports the include,exclude syntax specific to this program
	router.HandleFunc("/validatequery", func(w http.ResponseWriter, r *http.Request) {
		rest, _, err := ParseQuery(r.URL.Query().Get("query"))
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
			if _, err := ParseQueryStrict(rest[1:]); err != nil {
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
		var o *Object
		var found bool
		switch strings.ToLower(vars["locateby"]) {
		case "dn", "distinguishedname":
			o, found = AllObjects.Find(DistinguishedName, AttributeValueString(vars["id"]))
		case "sid":
			sid, err := SIDFromString(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = AllObjects.Find(ObjectSid, AttributeValueSID(sid))
		case "guid":
			u, err := uuid.FromString(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = AllObjects.Find(ObjectGUID, AttributeValueGUID(u))
		}
		if !found {
			w.WriteHeader(404) // bad request
			w.Write([]byte("Object not found"))
			return
		}

		if r.FormValue("format") == "objectdump" {
			w.WriteHeader(200)
			w.Write([]byte(o.String()))
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
			CanPwn:            make(map[string][]string),
			PwnableBy:         make(map[string][]string),
		}

		for attr, values := range o.Attributes {
			od.Attributes[attr.String()] = values.StringSlice()
		}

		if r.FormValue("format") == "json" {
			w.WriteHeader(200)
			e := qjson.NewEncoder(w)
			e.SetIndent("", "  ")
			e.Encode(od.Attributes)
			return
		}

		for target, pwnmethod := range o.CanPwn {
			od.CanPwn[target.DN()] = pwnmethod.GetMethodBitmap().StringSlice()
		}

		for target, pwnmethod := range o.PwnableBy {
			od.PwnableBy[target.DN()] = pwnmethod.GetMethodBitmap().StringSlice()
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
		w.WriteHeader(200)
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

		anonymize, _ := ParseBool(vars["anonymize"])

		mode := vars["mode"]
		if mode == "" {
			mode = "normal"
		}

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

		alldetails, _ := ParseBool(vars["alldetails"])
		force, _ := ParseBool(vars["force"])

		var includeobjects *Objects
		var excludeobjects *Objects

		var excludequery Query

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

		rest, includequery, err := ParseQuery(query)
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
			if excludequery, err = ParseQueryStrict(rest[1:]); err != nil {
				w.WriteHeader(400) // bad request
				encoder.Encode(fmt.Sprintf("Error parsing ldap query: %v", err))
				return
			}
		}

		includeobjects = AllObjects.Filter(func(o *Object) bool {
			// Domain Admins and Enterprise Admins groups
			return includequery.Evaluate(o)
		})

		if excludequery != nil {
			excludeobjects = AllObjects.Filter(func(o *Object) bool {
				// Domain Admins and Enterprise Admins groups
				return excludequery.Evaluate(o)
			})
		}

		var selectedmethods []PwnMethod
		for potentialmethod := range vars {
			if method, ok := PwnMethodString(potentialmethod); ok == nil {
				// enabled, _ := value.(bool)
				// if enabled {
				selectedmethods = append(selectedmethods, method)
				// }
			}
		}
		// If everything is deselected, select everything
		if len(selectedmethods) == 0 {
			selectedmethods = PwnMethodValues()
		}

		var methods PwnMethodBitmap
		for _, m := range selectedmethods {
			methods = methods.Set(m)
		}
		pg := AnalyzeObjects(includeobjects, excludeobjects, methods, mode, maxdepth, maxoutgoing, Probability(minprobability))

		var targets, users, computers, groups, others int
		for _, node := range pg.Nodes {
			if node.Target {
				targets++
				continue
			}
			switch node.Object.Type() {
			case ObjectTypeComputer:
				computers++
			case ObjectTypeGroup:
				groups++
			case ObjectTypeUser:
				users++
			default:
				others++
			}
		}

		if len(pg.Nodes) > 1000 && !force {
			w.WriteHeader(413) // too big payload response
			if strings.HasPrefix(mode, "inverted") {
				fmt.Fprintf(w, "Too much data, %v targets can pwn %v users, %v groups, %v computers and %v others via %v links. Use force option to potentially crash your browser or <a href=\"%v\">download a GML file.</a>", targets, users, groups, computers, others, len(pg.Connections), "/export-graph?format=xgmml&"+r.URL.RawQuery)
			} else {
				fmt.Fprintf(w, "Too much data, %v targets can be pwned by %v users, %v groups, %v computers and %v others via %v links. Use force option to potentially crash your browser or <a href=\"%v\">download a GML file.</a>.", targets, users, groups, computers, others, len(pg.Connections), "/export-graph?format=xgmml&"+r.URL.RawQuery)
			}
			return
		}

		cytograph, err := GenerateCytoscapeJS(pg, alldetails)
		if err != nil {
			w.WriteHeader(500)
			encoder.Encode("Error during graph creation")
			return
		}

		if anonymize {
			for _, node := range cytograph.Elements {
				if node.Group == "nodes" {
					node.Data["label"] = StringScrambler(node.Data["label"].(string))
					node.Data[DistinguishedName.String()] = StringScrambler(node.Data[DistinguishedName.String()].(string))
					node.Data[Name.String()] = StringScrambler(node.Data[Name.String()].(string))
					node.Data[DisplayName.String()] = StringScrambler(node.Data[DisplayName.String()].(string))
					node.Data[SAMAccountName.String()] = StringScrambler(node.Data[SAMAccountName.String()].(string))
				}
			}
		}

		response := struct {
			Reversed bool `json:"reversed"`

			Users     int `json:"users"`
			Computers int `json:"computers"`
			Groups    int `json:"groups"`
			Others    int `json:"others"`

			Targets int `json:"targets"`
			Total   int `json:"total"`
			Links   int `json:"links"`

			Elements *CytoElements `json:"elements"`
		}{
			Reversed: mode != "normal",

			Users:     users,
			Computers: computers,
			Groups:    groups,
			Others:    others,

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

		alldetails, err := ParseBool(uq.Get("alldetails"))
		if err != nil {
			alldetails = true
		}

		var includeobjects *Objects
		var excludeobjects *Objects

		var excludequery Query

		rest, includequery, err := ParseQuery(r.URL.Query().Get("query"))
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
			if excludequery, err = ParseQueryStrict(rest[1:]); err != nil {
				w.WriteHeader(400) // bad request
				fmt.Fprintf(w, "Error parsing ldap query: %v", err)
				return
			}
		}

		includeobjects = AllObjects.Filter(func(o *Object) bool {
			// Domain Admins and Enterprise Admins groups
			return includequery.Evaluate(o)
		})

		if excludequery != nil {
			excludeobjects = AllObjects.Filter(func(o *Object) bool {
				// Domain Admins and Enterprise Admins groups
				return excludequery.Evaluate(o)
			})
		}

		var selectedmethods []PwnMethod
		for potentialmethod, values := range uq {
			if method, ok := PwnMethodString(potentialmethod); ok == nil {
				enabled, _ := ParseBool(values[0])
				if len(values) == 1 && enabled {
					selectedmethods = append(selectedmethods, method)
				}
			}
		}
		// If everything is deselected, select everything
		if len(selectedmethods) == 0 {
			selectedmethods = PwnMethodValues()
		}

		var methods PwnMethodBitmap
		for _, m := range selectedmethods {
			methods = methods.Set(m)
		}
		pg := AnalyzeObjects(includeobjects, excludeobjects, methods, mode, maxdepth, maxoutgoing, 1)

		idmap := make(map[*Object]int)
		var id int
		for _, node := range pg.Nodes {
			idmap[node.Object] = id
			id++
		}

		// Make browser download this
		filename := AllObjects.Domain + "-analysis-" + time.Now().Format(time.RFC3339)

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
					for attribute, values := range node.Attributes {
						valuesjoined := strings.Join(values.StringSlice(), ", ")
						if IsASCII(valuesjoined) {
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
`, idmap[pwn.Source], idmap[pwn.Target], methods.JoinedString())
			}

			w.Write([]byte("]\n"))

		case "xgmml":
			graph := NewXGMMLGraph()

			for id, node := range pg.Nodes {
				object := node.Object
				xmlnode := XGMMLNode{
					Id:    id,
					Label: object.Label(),
				}

				if alldetails {
					for attribute, values := range object.Attributes {
						valuesjoined := strings.Join(values.StringSlice(), ", ")
						if IsASCII(valuesjoined) {
							xmlnode.Attributes = append(xmlnode.Attributes, XGMMLAttribute{
								Name:  attribute.String(),
								Value: valuesjoined,
							})
						}
					}
				}
				graph.Nodes = append(graph.Nodes, xmlnode)
			}

			for _, pwn := range pg.Connections {
				graph.Edges = append(graph.Edges, XGMMLEdge{
					Source: idmap[pwn.Source],
					Target: idmap[pwn.Target],
					Label:  pwn.GetMethodBitmap().JoinedString(),
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

		rest, includequery, err := ParseQuery(query)
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

		objects := AllObjects.Filter(func(o *Object) bool {
			return includequery.Evaluate(o)
		})

		dns := make([]string, len(objects.AsArray()))

		for i, o := range objects.AsArray() {
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

		rest, includequery, err := ParseQuery(query)
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

		objects := AllObjects.Filter(func(o *Object) bool {
			return includequery.Evaluate(o)
		})

		err = encoder.Encode(objects.AsArray())
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
		for _, object := range AllObjects.AsArray() {
			if object.Type() == ObjectTypeUser &&
				object.OneAttrString(MetaWorkstation) != "1" &&
				object.OneAttrString(MetaServer) != "1" &&
				object.OneAttrString(MetaAccountDisabled) != "1" {
				lastlogin, _ := object.AttrTimestamp(LastLogon)
				lastlogints, _ := object.AttrTimestamp(LastLogonTimestamp)
				last, _ := object.AttrTimestamp(PwdLastSet)

				expires, _ := object.AttrTimestamp(AccountExpires)
				created, _ := object.AttrTimestamp(WhenCreated)
				changed, _ := object.AttrTimestamp(WhenChanged)

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

					Unconstrained: object.OneAttrString(MetaUnconstrainedDelegation) == "1",
					Workstation:   object.OneAttrString(MetaWorkstation) == "1",
					Server:        object.OneAttrString(MetaServer) == "1",
					Enabled:       object.OneAttrString(MetaAccountDisabled) != "1",
					CantChangePwd: object.OneAttrString(MetaPasswordCantChange) == "1",
					NoExpirePwd:   object.OneAttrString(MetaPasswordNoExpire) == "1",
					NoRequirePwd:  object.OneAttrString(MetaPasswordNotRequired) == "1",
					HasLAPS:       object.OneAttrString(MetaLAPSInstalled) == "1",
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

	router.HandleFunc("/statistics", func(w http.ResponseWriter, r *http.Request) {
		var result struct {
			Statistics map[string]int `json:"statistics"`
		}

		result.Statistics = make(map[string]int)

		for objecttype, count := range AllObjects.Statistics() {
			if objecttype == 0 {
				continue // skip the dummy one
			}
			result.Statistics[ObjectType(objecttype).String()] += count
		}

		var pwnlinks int
		for _, object := range AllObjects.AsArray() {
			pwnlinks += len(object.CanPwn)
		}
		result.Statistics["Total"] = len(AllObjects.AsArray())
		result.Statistics["PwnConnections"] = pwnlinks

		data, _ := json.MarshalIndent(result, "", "  ")
		w.Write(data)
	})
	// Shutdown
	router.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) {
		quit <- true
	})
	// Serve embedded static files, or from html folder if it exists
	var assets fs.FS
	assets = embeddedassets

	if _, err := os.Stat("html"); !os.IsNotExist(err) {
		// Use local files if they exist
		if osf, err := osfs.NewFS(); err == nil {
			assets, _ = gofs.NewFs(osf)
		}
	}

	// Rendered markdown file
	// router.HandleFunc("/readme", func(w http.ResponseWriter, r *http.Request) {
	// 	readmefile, _ := assets.Open("readme.MD")
	// 	var readmedata bytes.Buffer
	// 	io.Copy(&readmedata, readmefile)
	// 	w.Write(markdown.ToHTML(readmedata.Bytes(), nil, nil))
	// })
	router.PathPrefix("/").Handler(http.FileServer(http.FS(FSPrefix{
		Prefix: "html",
		FS:     assets,
	})))

	log.Info().Msgf("Listening - navigate to %v ... (ctrl-c or similar to quit)", bind)

	return srv
}
