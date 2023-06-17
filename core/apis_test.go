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

package core_test

import (
	"errors"
	"testing"

	core "core-building-block/core"
	genmocks "core-building-block/core/mocks"
	"core-building-block/core/model"

	"github.com/rokwire/core-auth-library-go/v3/tokenauth"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/stretchr/testify/mock"
	"gotest.tools/assert"
)

func buildTestCoreAPIs(storage core.Storage) *core.APIs {
	return core.NewCoreAPIs("local", "1.1.1", "build", "core", storage, nil, nil, nil)
}

//Services

func TestSerGetVersion(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := buildTestCoreAPIs(&storage)
	got := coreAPIs.GetVersion()
	want := "1.1.1"

	assert.Equal(t, got, want, "result is different")
}

func TestSerGetAuthTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := buildTestCoreAPIs(&storage)
	l := logs.NewLogger("test", nil).NewLog("1", logs.RequestContext{})
	got := coreAPIs.Services.SerGetAuthTest(l)
	want := "Services - Auth - test"

	assert.Equal(t, got, want, "result is different")
}

func TestSerGetCommonTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := buildTestCoreAPIs(&storage)

	l := logs.NewLogger("test", nil).NewLog("1", logs.RequestContext{})
	got := coreAPIs.Services.SerGetCommonTest(l)
	want := "Services - Common - test"

	assert.Equal(t, got, want, "result is different")
}

///

//Administration

func TestAdmGetTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := buildTestCoreAPIs(&storage)

	got := coreAPIs.Administration.AdmGetTest()
	want := "Admin - test"

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

func TestAdmCreateConfig(t *testing.T) {
	anyConfig := mock.AnythingOfType("model.Config")
	storage := genmocks.Storage{}
	storage.On("FindOrganization", "system_org_id").Return(&model.Organization{ID: "system_org_id", System: true}, nil)
	storage.On("FindApplication", nil, "admin_app_id").Return(&model.Application{ID: "admin_app_id", Admin: true}, nil)
	storage.On("InsertConfig", anyConfig).Return(nil)

	coreAPIs := buildTestCoreAPIs(&storage)

	trueVal := true
	systemClaims := tokenauth.Claims{AppID: "admin_app_id", OrgID: "system_org_id", System: true}
	config := model.Config{ID: model.ConfigTypeEnv, AppID: "admin_app_id", OrgID: "system_org_id", Type: model.ConfigTypeEnv, Data: model.EnvConfigData{AllowLegacyRefresh: &trueVal}}
	newConfig, err := coreAPIs.Administration.AdmCreateConfig(config, &systemClaims)
	if err != nil {
		t.Error("we are not expecting error")
		return
	}
	if newConfig == nil || newConfig.ID == "" {
		t.Error("config must be returned with valid id")
		return
	}

	//second case - error
	storage2 := genmocks.Storage{}
	storage2.On("FindOrganization", "system_org_id").Return(&model.Organization{ID: "system_org_id", System: true}, nil)
	storage2.On("FindApplication", nil, "admin_app_id").Return(&model.Application{ID: "admin_app_id", Admin: true}, nil)
	storage2.On("InsertConfig", anyConfig).Return(errors.New("error occured"))

	coreAPIs = buildTestCoreAPIs(&storage2)

	_, err = coreAPIs.Administration.AdmCreateConfig(config, &systemClaims)
	if err == nil {
		t.Error("we are expecting error")
		return
	}

	errText := err.Error()
	assert.Equal(t, errText, "core-building-block/core.(*application).admCreateConfig() error inserting config: error occured", "error is different: "+err.Error())
}

///

//System

func TestSysGetOrganization(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("FindOrganization", "_id").Return(&model.Organization{ID: "_id"}, nil)
	coreAPIs := buildTestCoreAPIs(&storage)

	getOrganization, _ := coreAPIs.System.SysGetOrganization("_id")

	if getOrganization == nil {
		t.Errorf("Error on getting the organization")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("FindOrganization").Return(&model.Organization{ID: "_id"}, nil)
	coreAPIs = buildTestCoreAPIs(&storage)

	err, _ := coreAPIs.System.SysGetOrganization("_id")

	if err == nil {
		t.Error("We are expecting error")
		return
	}

}

func TestSysGetOrganizations(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("FindOrganizations").Return([]model.Organization{}, nil)
	coreAPIs := buildTestCoreAPIs(&storage)

	getOrganization, _ := coreAPIs.System.SysGetOrganizations()

	if getOrganization == nil {
		t.Errorf("Error on getting the organizations")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("FindOrganizations").Return([]model.Organization{}, nil)
	coreAPIs = buildTestCoreAPIs(&storage)

	err, _ := coreAPIs.System.SysGetOrganizations()

	if err == nil {
		t.Error("We are expecting error")
		return
	}
}

func TestSysGetApplication(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("FindApplication", nil, "_id").Return(&model.Application{ID: "_id"}, nil)
	coreAPIs := buildTestCoreAPIs(&storage)

	getApplication, _ := coreAPIs.System.SysGetApplication("_id")

	if getApplication == nil {
		t.Errorf("Error on geting the application")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("FindApplication").Return(&model.Application{ID: "_id"}, nil)
	coreAPIs = buildTestCoreAPIs(&storage)

	err, _ := coreAPIs.System.SysGetApplication("_id")

	if err == nil {
		t.Error("We are expecting error")
		return
	}
}

func TestSysGetApplications(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("FindApplications").Return([]model.Application{}, nil)
	app := buildTestCoreAPIs(&storage)

	getApplications, _ := app.System.SysGetApplications()

	if getApplications == nil {
		t.Errorf("Error on getting the appllications")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("FindApplications").Return([]model.Application{}, nil)
	app = buildTestCoreAPIs(&storage)

	err, _ := app.System.SysGetApplications()

	if err == nil {
		t.Error("We are expecting error")
		return
	}
}

///

//Encryption

func TestEncGetTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := buildTestCoreAPIs(&storage)

	got := coreAPIs.Encryption.EncGetTest()
	want := "Enc - test"

	assert.Equal(t, got, want, "result is different")
}

func TestCreateApplication(t *testing.T) {
	/*storage := genmocks.Storage{}
	versions := []string{"v1.1.0", "v1.2.0"}

	appObj := model.Application{Name: "name", Versions: versions}

	storage.On("InsertApplication", appObj).Return(&appObj, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil, nil, nil)

	application, _ := app.Administration.AdmCreateApplication("name", versions)
	if application == nil {
		t.Error("application is nil")
		return
	}

	storage2 := genmocks.Storage{}
	versions = []string{"v1.1.0", "v1.2.0"}
	storage2.On("InsertApplication", model.Application{Name: "name", Versions: versions}).Return(nil, errors.New("error occured"))

	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage2, nil)

	_, err := app.Administration.AdmCreateApplication("name", versions)
	if err == nil {
		t.Error("we are expecting error")
		return
	}
	assert.Equal(t, err.Error(), "error occured", "error is different") */
}

///

//BBs

func TestBBsGetTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := buildTestCoreAPIs(&storage)

	got := coreAPIs.BBs.BBsGetTest()
	want := "BBs - test"

	assert.Equal(t, got, want, "result is different")
}

///
