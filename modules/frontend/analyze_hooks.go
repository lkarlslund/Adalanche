package frontend

type AnalyzeHook func(*WebService) error

var analyzeHooks []AnalyzeHook

func AddAnalyzeHook(h AnalyzeHook) {
	analyzeHooks = append(analyzeHooks, h)
}

func (ws *WebService) Status() WebServiceStatus {
	return ws.status
}
