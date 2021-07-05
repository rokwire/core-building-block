package core_test

import (
	"testing"

	core "core-building-block/core"
	core_model "core-building-block/core/model"
	genmocks "core-building-block/mocks"

	"gotest.tools/assert"
)

func TestAdmGetTest(t *testing.T) {
	storage := genmocks.Storage{}
	app := core.NewApplication("1.1.1", "build", &storage, nil)

	got := app.Administration.AdmGetTest()
	want := "Admin - test"

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

func TestAdmCreateGlobalConfig(t *testing.T) {
	storage := genmocks.Storage{}
	storage.On("CreateGlobalConfig", "setting").Return(&core_model.GlobalConfig{"setting"}, nil)

	app := core.NewApplication("1.1.1", "build", &storage, nil)

	gc, _ := app.Administration.AdmCreateGlobalConfig("setting")
	if gc == nil {
		t.Error("gc is nil")
		return
	}
	assert.Equal(t, gc.Setting, "setting", "setting is different")

	/*	//second case - error
		storage2 := genmocks.Storage{}
		app = core.NewApplication("1.1.1", "build", &storage2, nil)

		_, err := app.Administration.AdmCreateGlobalConfig("setting")
		if err == nil {
			t.Error("we are expecting error")
			return
		}
		assert.Equal(t, err.Error(), "error occured", "error is different") */

}
