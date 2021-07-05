package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/gomarkdown/markdown"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

func webservice(bind string) http.Server {
	router := mux.NewRouter()
	srv := http.Server{
		Addr:    bind,
		Handler: router,
	}
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
	router.HandleFunc("/details/{locateby}/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		var o *Object
		var found bool
		switch strings.ToLower(vars["locateby"]) {
		case "dn", "distinguishedname":
			o, found = AllObjects.Find(vars["id"])
		case "sid":
			sid, err := SIDFromString(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = AllObjects.FindSID(sid)
		case "guid":
			u, err := uuid.FromString(vars["id"])
			if err != nil {
				w.WriteHeader(400) // bad request
				w.Write([]byte(err.Error()))
				return
			}
			o, found = AllObjects.FindGUID(u)
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
			DistinguishedName string              `json:distinguishedname`
			Attributes        map[string][]string `json:attributes`
			CanPwn            map[string][]string `json:can_pwn`
			PwnableBy         map[string][]string `json:pwnable_by`
		}

		od := ObjectDetails{
			DistinguishedName: o.DN(),
			Attributes:        make(map[string][]string),
			CanPwn:            make(map[string][]string),
			PwnableBy:         make(map[string][]string),
		}

		for attr, values := range o.Attributes {
			od.Attributes[attr.Name()] = values
		}

		if r.FormValue("format") == "json" {
			w.WriteHeader(200)
			e := qjson.NewEncoder(w)
			e.SetIndent("", "  ")
			e.Encode(od.Attributes)
			return
		}

		for _, pwninfo := range o.CanPwn {
			od.CanPwn[pwninfo.Target.DN()] = append(od.CanPwn[pwninfo.Target.DN()], pwninfo.Method.String())
		}

		for _, pwninfo := range o.PwnableBy {
			od.PwnableBy[pwninfo.Target.DN()] = append(od.PwnableBy[pwninfo.Target.DN()], pwninfo.Method.String())
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
	router.HandleFunc("/cytograph.json", func(w http.ResponseWriter, r *http.Request) {
		uq := r.URL.Query()
		encoder := qjson.NewEncoder(w)
		encoder.SetIndent("", "  ")

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

		alldetails, _ := ParseBool(uq.Get("alldetails"))
		force, _ := ParseBool(uq.Get("force"))

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

		pg := AnalyzeObjects(includeobjects, excludeobjects, selectedmethods, mode, maxdepth)

		targetmap := make(map[*Object]bool)
		for _, target := range pg.Targets {
			targetmap[target] = true
		}

		var targets, users, computers, groups, others int
		for _, object := range pg.Implicated {
			if targetmap[object] {
				targets++
				continue
			}
			switch object.Type() {
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

		if len(pg.Implicated) > 1000 && !force {
			w.WriteHeader(413) // too big payload response
			if strings.HasPrefix(mode, "inverted") {
				encoder.Encode(fmt.Sprintf("Too much data, %v targets can pwn %v users, %v groups, %v computers and %v others via %v links. Use force option to potentially crash your browser.", targets, users, groups, computers, others, len(pg.Connections)))
			} else {
				encoder.Encode(fmt.Sprintf("Too much data, %v targets can be pwned by %v users, %v groups, %v computers and %v others via %v links. Use force option to potentially crash your browser.", targets, users, groups, computers, others, len(pg.Connections)))
			}
			return
		}

		cytograph, err := GenerateCytoscapeJS(pg, alldetails)
		if err != nil {
			w.WriteHeader(500)
			encoder.Encode("Error during graph creation")
			return
		}

		response := struct {
			Users     int `json:"users"`
			Computers int `json:"computers"`
			Groups    int `json:"groups"`
			Others    int `json:"others"`

			Targets int `json:"targets"`
			Total   int `json:"total"`
			Links   int `json:"links"`

			Elements *CytoElements `json:"elements"`
		}{
			Total: len(pg.Implicated),

			Targets: targets,

			Users:     users,
			Computers: computers,
			Groups:    groups,
			Others:    others,

			Links: len(pg.Connections),

			Elements: &cytograph.Elements,
		}

		err = encoder.Encode(response)
		if err != nil {
			w.WriteHeader(500)
			encoder.Encode("Error during JSON encoding")
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
		}
		var result []info
		for _, object := range AllObjects.AsArray() {
			if object.Type() == ObjectTypeUser &&
				object.OneAttr(MetaWorkstation) != "1" &&
				object.OneAttr(MetaServer) != "1" &&
				object.OneAttr(MetaAccountDisabled) != "1" {
				lastlogin, ok := object.AttrTimestamp(LastLogon)
				lastlogints, ok := object.AttrTimestamp(LastLogonTimestamp)
				last, ok := object.AttrTimestamp(PwdLastSet)

				expires, ok := object.AttrTimestamp(AccountExpires)
				created, ok := object.AttrTimestamp(WhenCreated)
				changed, ok := object.AttrTimestamp(WhenChanged)
				if !ok {
				}
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

					Unconstrained: object.OneAttr(MetaUnconstrainedDelegation) == "1",
					Workstation:   object.OneAttr(MetaWorkstation) == "1",
					Server:        object.OneAttr(MetaServer) == "1",
					Enabled:       object.OneAttr(MetaAccountDisabled) != "1",
					CantChangePwd: object.OneAttr(MetaPasswordCantChange) == "1",
					NoExpirePwd:   object.OneAttr(MetaPasswordNoExpire) == "1",
					NoRequirePwd:  object.OneAttr(MetaPasswordNotRequired) == "1",
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
		ctx, _ := context.WithTimeout(nil, time.Second*15)
		srv.Shutdown(ctx)
	})
	// Serve embedded static files, or from html folder if it exists
	var assets http.FileSystem
	assets = assetFS()
	if _, err := os.Stat("html"); !os.IsNotExist(err) {
		// Use local files if they exist
		assets = http.Dir("html")
	}

	// Rendered markdown file
	router.HandleFunc("/readme", func(w http.ResponseWriter, r *http.Request) {
		readmefile, _ := assets.Open("readme.MD")
		var readmedata bytes.Buffer
		io.Copy(&readmedata, readmefile)
		w.Write(markdown.ToHTML(readmedata.Bytes(), nil, nil))
	})
	router.PathPrefix("/").Handler(http.FileServer(assets))

	log.Debug().Msgf("Listening - navigate to %v ...", bind)

	return srv
}
