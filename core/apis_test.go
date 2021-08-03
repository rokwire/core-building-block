package core_test

import (
	"errors"
	"testing"

	core "core-building-block/core"
	genmocks "core-building-block/core/mocks"
	"core-building-block/core/model"
	core_model "core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"

	"gotest.tools/assert"
)

//Services

func TestSerGetVersion(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	got := coreAPIs.GetVersion()
	want := "1.1.1"

	assert.Equal(t, got, want, "result is different")
}

func TestSerGetAuthTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	l := log.NewLogger("test", nil).NewLog("1", log.RequestContext{})
	got := coreAPIs.Services.SerGetAuthTest(l)
	want := "Services - Auth - test"

	assert.Equal(t, got, want, "result is different")
}

func TestSerGetCommonTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	l := log.NewLogger("test", nil).NewLog("1", log.RequestContext{})
	got := coreAPIs.Services.SerGetCommonTest(l)
	want := "Services - Common - test"

	assert.Equal(t, got, want, "result is different")
}

///

//Administration

func TestAdmGetTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	got := coreAPIs.Administration.AdmGetTest()
	want := "Admin - test"

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

func TestAdmCreateGlobalConfig(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("GetGlobalConfig").Return(nil, nil)
	storage.On("CreateGlobalConfig", "setting").Return(&core_model.GlobalConfig{Setting: "setting"}, nil)

	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	gc, _ := app.Administration.AdmCreateGlobalConfig("setting")
	if gc == nil {
		t.Error("gc is nil")
		return
	}
	assert.Equal(t, gc.Setting, "setting", "setting is different")

	//second case - error
	storage2 := genmocks.Storage{}
	storage2.On("GetGlobalConfig").Return(nil, nil)
	storage2.On("CreateGlobalConfig", "setting").Return(nil, errors.New("error occured"))

	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage2, nil)

	_, err := app.Administration.AdmCreateGlobalConfig("setting")
	if err == nil {
		t.Error("we are expecting error")
		return
	}
	assert.Equal(t, err.Error(), "core-building-block/core.(*application).admCreateGlobalConfig() error inserting global config: error occured", "error is different: "+err.Error())
}

func TestAdmGetOrganization(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("GetOrganization", "_id").Return(&model.Organization{ID: "_id"}, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	getOrganization, _ := app.Administration.AdmGetOrganization("_id")

	if getOrganization == nil {
		t.Errorf("Error on geting the organization")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("GetOrganization").Return(&model.Organization{ID: "_id"}, nil)
	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	err, _ := app.Administration.AdmGetOrganization("_id")

	if err == nil {
		t.Error("We are expecting error")
		return
	}

}

func TestGetOrganizations(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("GetOrganizations").Return([]model.Organization{}, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	getOrganization, _ := app.Administration.AdmGetOrganizations()

	if getOrganization == nil {
		t.Errorf("Error on geting the organizations")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("GetOrganizations").Return([]model.Organization{}, nil)
	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	err, _ := app.Administration.AdmGetOrganizations()

	if err == nil {
		t.Error("We are expecting error")
		return
	}
}

///

//Encryption

func TestEncGetTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	got := coreAPIs.Encryption.EncGetTest()
	want := "Enc - test"

	assert.Equal(t, got, want, "result is different")
}

///

//BBs

func TestBBsGetTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	got := coreAPIs.BBs.BBsGetTest()
	want := "BBs - test"

	assert.Equal(t, got, want, "result is different")
}

///

func TestAdmCreateGlobalPermission(t *testing.T) {

}
