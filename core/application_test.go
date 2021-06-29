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

type StorageListenerMock struct {
	mock.Mock
}

type ListenerMock struct {
	mock.Mock
}

/*
func (r StorageMock) GetAllUsers() ([]User, error) {
	args := r.Called()
	users := []User{
		{"mock", "*****"},
	}
	return users, args.Error(1)
} */

func TestStart(t *testing.T) {
	/*	storage := StorageMock{}
		app := NewApplication("1.1.1", "build", storage, nil)

		storageListener := app.storageListener
		if len(listeners) != 0 {
			t.Error("listeners is not empty")
		}

		app.S(StorageListenerMock{})

		listeners = app.listeners
		if len(listeners) != 1 {
			t.Error("listeners must has 1 listener")
		} */
}

func TestAddListener(t *testing.T) {
	storage := StorageMock{}
	app := NewApplication("1.1.1", "build", storage, nil)

	listeners := app.listeners
	if len(listeners) != 0 {
		t.Error("listeners is not empty")
	}

	app.AddListener(ListenerMock{})

	listeners = app.listeners
	if len(listeners) != 1 {
		t.Error("listeners must has 1 listener")
	}
}

/*
func TestAdmCreateGlobalConfig2(t *testing.T) {

		repository := UserRepositoryMock{}
		repository.On("GetAllUsers").Return([]User{}, nil)

		service := UserService{repository}
		users, _ := service.GetUser()
		for i := range users {
			assert.Equal(t, users[i].Password, "*****", "user password must be encrypted")
		}
		fmt.Println(users)

} */
