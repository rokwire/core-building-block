package web

import (
	"encoding/json"
	"time"

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

func defStringArray(pointer *[]string) []string {
	if pointer == nil {
		return []string{}
	}
	return *pointer
}

func defTimestamp(pointer *string) time.Time {
	if pointer == nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, *pointer)

	if err != nil {
		return time.Time{}
	}
	return t
}

func defBool(pointer *string) bool {
	if pointer == nil {
		return false
	}
	return *pointer == "true"
}

func interfaceToJSON(item interface{}) (string, error) {
	json, err := json.Marshal(item)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "interface", nil, err)
	}
	return string(json), nil
}
