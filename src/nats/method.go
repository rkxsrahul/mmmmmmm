package nats

import (
	"encoding/json"
	"log"
	"strings"
)

func findCategory(mapd map[string]string) string {
	for _, v := range mapd {
		return v
	}
	return ""
}

func headerFileSlug(header string) string {
	header = strings.ToLower(header)
	header = strings.Replace(header, " ", "-", -1)
	header = strings.Replace(header, "/", "-", -1)
	return header + ".sh"
}

type BodyData struct {
	Method string `json:"method"`
	UUID   string `json:"uuid"`
	URL    string `json:"url"`
	Status string `json:"status"`
}

func convertDatatoJSON(bdata []byte) BodyData {
	var data BodyData
	err := json.Unmarshal(bdata, &data)
	if err != nil {
		log.Println(err)
	}
	return data
}
