package core

/*
import (
	"core-building-block/core/model"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"gotest.tools/assert"
)

func TestAdmGetTest(t *testing.T) {
	storage := StorageMock{}
	app := NewApplication("1.1.1", "build", storage, nil)

	got := app.admGetTest()
	want := "Admin - test"

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

type storageMockAdmCreateGlobalConfig1 struct {
	mock.Mock
}

func (r storageMockAdmCreateGlobalConfig1) SetStorageListener(storageListener StorageListener) {}
func (r storageMockAdmCreateGlobalConfig1) CreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	return &model.GlobalConfig{Setting: setting}, nil
}
func (r storageMockAdmCreateGlobalConfig1) GetGlobalConfig() (*model.GlobalConfig, error) {
	return nil, nil
}

type storageMockAdmCreateGlobalConfig2 struct {
	mock.Mock
}

func (r storageMockAdmCreateGlobalConfig2) SetStorageListener(storageListener StorageListener) {}
func (r storageMockAdmCreateGlobalConfig2) CreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	return nil, errors.New("error occured")
}
func (r storageMockAdmCreateGlobalConfig2) GetGlobalConfig() (*model.GlobalConfig, error) {
	return nil, nil
}

func TestAdmCreateGlobalConfig(t *testing.T) {
	storage := storageMockAdmCreateGlobalConfig1{}
	//storage.On("CreateGlobalConfig").Return(model.GlobalConfig{"settingg"}, nil)

	app := NewApplication("1.1.1", "build", storage, nil)

	gc, _ := app.admCreateGlobalConfig("setting")
	if gc == nil {
		t.Error("gc is nil")
		return
	}
	if gc.Setting != "setting" {
		t.Errorf("got %q, wanted %q", gc.Setting, "setting")
		return
	}
	assert.Equal(t, gc.Setting, "setting", "setting is different")

	//second case - error
	storage2 := storageMockAdmCreateGlobalConfig2{}
	app = NewApplication("1.1.1", "build", storage2, nil)

	_, err := app.admCreateGlobalConfig("setting")
	if err == nil {
		t.Error("we are expecting error")
		return
	}
	assert.Equal(t, err.Error(), "error occured", "error is different")

}
*/
