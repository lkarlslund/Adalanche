package frontend

// Status returns how far the web service is with loading data.
func (ws *WebService) Status() WebServiceStatus {
	return ws.status
}
