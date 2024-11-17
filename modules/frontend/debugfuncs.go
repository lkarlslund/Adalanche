package frontend

import (
	"github.com/gin-gonic/gin"
	"github.com/lkarlslund/adalanche/modules/engine"
)

func debugfuncs(ws *WebService) {
	ws.Router.GET("/debug/attributes", func(c *gin.Context) {
		c.JSON(200, engine.AttributeInfos())
	})
	ws.Router.GET("/debug/edges", func(c *gin.Context) {
		c.JSON(200, engine.EdgeInfos())
	})
}
