package core

import (
	"core-building-block/core/model"
	"testing"

	"github.com/stretchr/testify/mock"
)

type StorageMock struct {
	mock.Mock
}

func (r StorageMock) SetStorageListener(storageListener StorageListener) {
}

func (r StorageMock) CreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	return nil, nil
}

func (r StorageMock) GetGlobalConfig() (*model.GlobalConfig, error) {
	return nil, nil
}

/*
func (r StorageMock) GetAllUsers() ([]User, error) {
	args := r.Called()
	users := []User{
		{"mock", "*****"},
	}
	return users, args.Error(1)
} */

func TestAdmGetTest(t *testing.T) {
	storage := StorageMock{}
	app := NewApplication("1.1.1", "build", storage, nil)

	got := app.admGetTest()
	want := "Admin - test"

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

func TestAdmCreateGlobalConfig(t *testing.T) {
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
