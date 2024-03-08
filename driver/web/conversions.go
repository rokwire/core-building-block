// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

func convert[T any, F any](val F) (*T, error) {
	if isNil(val) {
		return nil, nil
	}

	bytes, err := json.Marshal(val)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "value", nil, err)
	}

	var out T
	err = json.Unmarshal(bytes, &out)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "value", nil, err)
	}

	return &out, nil
}

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}

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

func defBool(pointer *bool) bool {
	if pointer == nil {
		return false
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
