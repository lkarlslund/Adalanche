package frontend

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireData is a middleware that ensures that a certain level of data readynesss is available or fails the request
func (ws *WebService) RequireData(minimumStatus WebServiceStatus) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		if ws.status < minimumStatus {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "no data"})
		}
	}
}
