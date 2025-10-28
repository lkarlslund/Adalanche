package aql

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/lkarlslund/adalanche/modules/persistence"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func init() {
	// AQL support
	frontend.AddOption(func(ws *frontend.WebService) error {
		aql := ws.API.Group("aql")
		aql.GET("validatequery", ws.RequireData(frontend.Ready), func(c *gin.Context) {
			querytext := strings.Trim(c.Query("query"), " \n\r")
			if querytext != "" {
				_, err := ParseAQLQuery(querytext, ws.SuperGraph)
				if err != nil {
					c.String(500, err.Error())
					return
				}
			}
			c.JSON(200, gin.H{"success": true})
		})

		// Graph based query analysis - core functionality
		aql.POST("analyze", ws.RequireData(frontend.Ready), func(c *gin.Context) {
			params := make(map[string]any)
			err := c.ShouldBindBodyWith(&params, binding.JSON)

			if err != nil {
				c.String(500, err.Error())
				return
			}

			query := params["query"]

			resolver, err := ParseAQLQuery(fmt.Sprintf("%v", query), ws.SuperGraph)
			if err != nil {
				c.String(500, "Error parsing AQL query: %v", err)
				return
			}

			opts := NewResolverOptions()
			err = c.ShouldBindBodyWith(&opts, binding.JSON)
			if err != nil {
				ui.Warn().Msgf("Problem parsing resolver options: %v", err)
			}

			results, err := resolver.Resolve(opts)
			if err != nil {
				c.String(500, "Error resolving AQL query: %v", err)
				return
			}

			for _, postprocessor := range frontend.PostProcessors {
				*results = postprocessor(*results)
			}

			ui.Info().Msgf("Graph query resulted in %v nodes", results.Order())

			// PruneIslands
			var prunedislands int
			if opts.PruneIslands {
				// Find island nodes
				for _, islandnode := range results.Islands() {
					results.DeleteNode(islandnode)
					prunedislands++
				}
			}
			if prunedislands > 0 {
				ui.Info().Msgf("Pruning islands removed %v nodes, leaving %v nodes", prunedislands, results.Order())
			}

			var objecttypes [256]int

			nodenamecounts := make(map[string]int)
			for node := range results.Nodes() {
				reference := results.GetNodeData(node, "reference")
				if reference != nil {
					nodenamecounts[reference.(string)]++
				}

				objecttypes[node.Type()]++
			}

			resulttypes := make(map[string]int)
			for i := range 256 {
				if objecttypes[i] > 0 {
					resulttypes[engine.NodeType(i).String()] = objecttypes[i]
				}
			}

			cytograph, err := frontend.GenerateCytoscapeJS(ws.SuperGraph, *results, false)
			if err != nil {
				c.String(500, "Error generating cytoscape graph: %v", err)
				return
			}

			response := struct {
				NodeNameCounts map[string]int `json:"nodecounts"`
				ResultTypes    map[string]int `json:"resulttypes"`

				Elements *frontend.CytoElements `json:"elements"`

				StartNodes int `json:"start_nodes"`
				EndNodes   int `json:"end_nodes"`

				Total int `json:"total"`
				Edges int `json:"edges"`
			}{
				// Reversed: mode != "normal", //FIXME

				ResultTypes:    resulttypes,
				NodeNameCounts: nodenamecounts,
				Total:          results.Order(),
				Edges:          results.Size(),

				Elements: &cytograph.Elements,
			}

			c.JSON(200, response)
		})

		userQueries := persistence.GetStorage[QueryDefinition]("queries", false)

		// List queries
		queries := ws.API.Group("backend/queries")

		queries.GET("", func(c *gin.Context) {
			// Create a string to query map and put all the predefined queries in that
			queryMap := make(map[string]QueryDefinition)
			var defaultQueryName string
			for _, q := range PredefinedQueries {
				queryMap[q.Name] = q
				if q.Default {
					defaultQueryName = q.Name
				}
			}

			// Merge the list of predefined queries and the user queries
			uq, _ := userQueries.List()
			for _, q := range uq {
				q.UserDefined = true
				// If user overrides default query, inherit this to their own
				if q.Name == defaultQueryName {
					q.Default = true
				}
				queryMap[q.Name] = q
			}
			querySlice := slices.Collect(maps.Values(queryMap))
			slices.SortFunc(querySlice, func(a, b QueryDefinition) int {
				if a.UserDefined == b.UserDefined {
					return strings.Compare(a.Name, b.Name)
				} else {
					if !a.UserDefined {
						return -1
					} else {
						return 1
					}
				}
			})
			c.JSON(200, querySlice)
		})
		queries.PUT(":name", func(ctx *gin.Context) {
			var query QueryDefinition
			err := ctx.ShouldBindJSON(&query)
			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusBadRequest, err)
				return
			}
			query.Name = ctx.Param("name")
			err = userQueries.Put(query)
			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusBadRequest, err)
				return
			}
			ctx.Status(http.StatusCreated)
		})
		queries.DELETE(":name", func(ctx *gin.Context) {
			err := userQueries.Delete(ctx.Param("name"))
			if err != nil {
				ctx.AbortWithStatusJSON(http.StatusNotFound, err)
				return
			}
			ctx.Status(http.StatusOK)
		})

		return nil
	})
}
