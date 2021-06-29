package core

import (
	"testing"
)

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
