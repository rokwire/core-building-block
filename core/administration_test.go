package core

import (
	"core-building-block/core/model"
	"testing"
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

/*
func (app *Application) admCreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	create, err := app.storage.CreateGlobalConfig(setting)
	if err != nil {
		return nil, err
	}
	return create, nil
} */

func TestAdmCreateGlobalConfig(t *testing.T) {
	storage := StorageMock{}
	storage.On("CreateGlobalConfig").Return(model.GlobalConfig{"settingg"}, nil)

	app := NewApplication("1.1.1", "build", storage, nil)

	gc, _ := app.admCreateGlobalConfig("setting")

	if gc.Setting != "setting" {
		t.Errorf("got %q, wanted %q", gc.Setting, "setting")
	}
	//got := app.admCreateGlobalConfig("setting")
	/*
		repository := UserRepositoryMock{}
		repository.On("GetAllUsers").Return([]User{}, nil)

		service := UserService{repository}
		users, _ := service.GetUser()
		for i := range users {
			assert.Equal(t, users[i].Password, "*****", "user password must be encrypted")
		}
		fmt.Println(users)
	*/
}
