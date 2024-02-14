package analyze

import (
	"github.com/gin-gonic/gin"
	"github.com/lkarlslund/adalanche/modules/engine"
)

func debugfuncs(ws *webservice) {
	ws.Router.GET("/debug/attributes", func(c *gin.Context) {
		c.JSON(200, engine.AttributeInfos())
	})
	ws.Router.GET("/debug/edges", func(c *gin.Context) {
		c.JSON(200, engine.EdgeInfos())
	})
}
