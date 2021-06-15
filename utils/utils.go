package utils

import (
	"fmt"
	"log"
	"net/http"
)

type Logging struct {
	ID     string
	UserID string
}

func (l Logging) Printf(data string) {
	log.Printf("ID:%s USER_ID:%s DATA:%s", l.ID, l.UserID, data)
}
func (l Logging) Fatalf(data string) {
	log.Fatalf(data)
}

func (l Logging) Println(data string) {
	log.Println("ID=", l.ID, "DATA=", l.UserID)
}

func (l Logging) Fatalln(data string) {
	log.Fatalln(data)
}

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
