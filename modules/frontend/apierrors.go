package frontend

import "github.com/gin-gonic/gin"

func AbortAPIError(c *gin.Context, status int, message string, errs ...error) {
	payload := gin.H{
		"status": "error",
		"error":  message,
	}
	if len(errs) > 0 && errs[0] != nil {
		payload["status_detail"] = errs[0].Error()
	}
	c.AbortWithStatusJSON(status, payload)
}

func AbortForbidden(c *gin.Context, message string, errs ...error) {
	AbortAPIError(c, 403, message, errs...)
}

func AbortInternal(c *gin.Context, message string, errs ...error) {
	AbortAPIError(c, 500, message, errs...)
}
