package core_test

import (
	"errors"
	"testing"

	core "core-building-block/core"
	genmocks "core-building-block/core/mocks"
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/logs"
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

	l := logs.NewLogger("test", nil).NewLog("1", logs.RequestContext{})
	got := coreAPIs.Services.SerGetAuthTest(l)
	want := "Services - Auth - test"

	assert.Equal(t, got, want, "result is different")
}

func TestSerGetCommonTest(t *testing.T) {
	storage := genmocks.Storage{}
	coreAPIs := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	l := logs.NewLogger("test", nil).NewLog("1", logs.RequestContext{})
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
	storage.On("CreateGlobalConfig", "setting").Return(&model.GlobalConfig{Setting: "setting"}, nil)

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

func TestAdmGetGlobalConfig(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("GetGlobalConfig").Return(&model.GlobalConfig{}, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	getGlobalConfig, _ := app.Administration.AdmGetGlobalConfig()

	if getGlobalConfig == nil {
		t.Errorf("Error on getting the global config")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("GetGlobalConfig").Return(&model.GlobalConfig{}, nil)
	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	err, _ := app.Administration.AdmGetGlobalConfig()

	if err == nil {
		t.Error("We are expecting error")
		return
	}
}

type updateGlobalConfigForTesting struct {
	setting string
}

func TestAdmUpdateGlobalConfig(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("GetGlobalConfig").Return(nil, nil)
	storage.On("SaveGlobalConfig", "setting").Return(&model.GlobalConfig{}, nil)

	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	gc := app.Administration.AdmUpdateGlobalConfig("setting")
	if gc == nil {
		t.Error("gc is nil")
		return
	}
	assert.Equal(t, nil, "setting", "setting is different")

	//second case - error
	storage2 := genmocks.Storage{}
	storage2.On("GetGlobalConfig").Return(nil, nil)
	storage2.On("SaveGlobalConfig", "setting").Return(nil, errors.New("error occured"))

	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage2, nil)

	err := app.Administration.AdmUpdateGlobalConfig("setting")
	if err == nil {
		t.Error("we are expecting error")
		return
	}
	assert.Equal(t, err.Error(), "core-building-block/core.(*application).admCreateGlobalConfig() error inserting global config: error occured", "error is different: "+err.Error())
}

func TestAdmGetOrganization(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("FindOrganization", "_id").Return(&model.Organization{ID: "_id"}, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	getOrganization, _ := app.Administration.AdmGetOrganization("_id")

	if getOrganization == nil {
		t.Errorf("Error on getting the organization")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("FindOrganization").Return(&model.Organization{ID: "_id"}, nil)
	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	err, _ := app.Administration.AdmGetOrganization("_id")

	if err == nil {
		t.Error("We are expecting error")
		return
	}
}

func TestGetOrganizations(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("LoadOrganizations").Return([]model.Organization{}, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	getOrganization, _ := app.Administration.AdmGetOrganizations()

	if getOrganization == nil {
		t.Errorf("Error on getting the organizations")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("LoadOrganizations").Return([]model.Organization{}, nil)
	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	err, _ := app.Administration.AdmGetOrganizations()

	if err == nil {
		t.Error("We are expecting error")
		return
	}
}
func TestAdmUpdateOrganization(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("AdmUpdateOrganization", "_id", "name", "type").Return(&model.Organization{ID: "_id", Name: "name", Type: "type"}, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	updateOrganization := app.Administration.AdmUpdateOrganization("_id", "name", "type", true, nil, nil)

	if updateOrganization == nil {
		t.Errorf("Error on updating the organization")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("AdmUpdateOrganization").Return(&model.Organization{ID: "_id", Name: "name", Type: "type"}, nil)
	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	err := app.Administration.AdmUpdateOrganization("_id", "name", "type", true, nil, nil)

	if err == nil {
		t.Error("We are expecting error")
		return
	}

}

func TestAdmGetApplication(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("FindApplication", "_id").Return(&model.Application{ID: "_id"}, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	getApplication, _ := app.Administration.AdmGetApplication("_id")

	if getApplication == nil {
		t.Errorf("Error on geting the application")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("FindApplication").Return(&model.Application{ID: "_id"}, nil)
	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	err, _ := app.Administration.AdmGetApplication("_id")

	if err == nil {
		t.Error("We are expecting error")
		return
	}
}

func TestGetApplications(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("FindApplications").Return([]model.Application{}, nil)
	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	getApplications, _ := app.Administration.AdmGetApplications()

	if getApplications == nil {
		t.Errorf("Error on getting the appllications")
	}
	// second case error
	storage2 := genmocks.Storage{}
	storage2.On("FindApplications").Return([]model.Application{}, nil)
	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	err, _ := app.Administration.AdmGetApplications()

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

type applicationForTesting struct {
	ID       string   `bson:"_id"`
	Name     string   `bson:"name"`
	Versions []string `bson:"versions"`
}

func TestAdmCreateApplication(t *testing.T) {

	versions := make([]string, 3)
	versions[0] = "V.1.1"
	versions[1] = "V.1.2"
	versions[2] = "V.1.3"
	storage := genmocks.Storage{}
	storage.On("InsertApplication", "_id", "name", versions).Return(&applicationForTesting{ID: "_id", Name: "name", Versions: versions}, nil)

	app := core.NewCoreAPIs("local", "1.1.1", "build", &storage, nil)

	ca, _ := app.Administration.AdmCreateApplication("name", versions)
	if ca == nil {
		t.Error("ca is nil")
		return
	}
	assert.Equal(t, ca.Name, ca.Versions)

	//second case - error
	storage2 := genmocks.Storage{}
	storage2.On("InsertApplication", "_id", "name", versions).Return(nil, errors.New("error occured"))

	app = core.NewCoreAPIs("local", "1.1.1", "build", &storage2, nil)

	_, err := app.Administration.AdmCreateApplication("name", versions)
	if err == nil {
		t.Error("we are expecting error")
		return
	}
	assert.Equal(t, err.Error(), "core-building-block/core.(*application).admCreateApplication() error inserting application: error occured", "error is different: "+err.Error())
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
