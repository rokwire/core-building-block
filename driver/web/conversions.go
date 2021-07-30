package web

import (
	"encoding/json"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logutils"
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

func interfaceToJSON(item interface{}) (string, error) {
	json, err := json.Marshal(item)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "interface", nil, err)
	}
	return string(json), nil
}
