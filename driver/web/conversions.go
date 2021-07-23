package web

import (
	"encoding/json"

	log "github.com/rokmetro/logging-library/loglib"
)

func defString(pointer *string) string {
	if pointer == nil {
		return ""
	}
	return *pointer
}

func defMap(pointer *map[string]interface{}) map[string]interface{} {
	if pointer == nil {
		return map[string]interface{}{}
	}
	return *pointer
}

func mapInterfaceToJSON(item interface{}) (string, error) {
	itemMap, ok := item.(map[string]interface{})
	if !ok {
		return "", log.NewErrorf("invalid item type: must be map[string]interface{}")
	}

	json, err := json.Marshal(itemMap)
	if err != nil {
		return "", log.WrapActionError(log.ActionMarshal, "map", nil, err)
	}

	return string(json), nil
}
