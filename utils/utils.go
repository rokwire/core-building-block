package utils

import (
	"fmt"
	"net/http"
)

//GetRequestLogData gets request log data
func GetRequestLogData(req *http.Request) string {
	if req == nil {
		return ""
	}

	method := req.Method
	path := req.URL.Path

	header := make(map[string][]string)
	for key, value := range req.Header {
		var logValue []string
		//do not log sensitive information
		if key == "Authorization" || key == "Csrf" {
			logValue = append(logValue, "---")
		} else {
			logValue = value
		}
		header[key] = logValue
	}
	result := fmt.Sprintf("%s %s %s", method, path, header)
	return result
}
