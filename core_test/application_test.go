package core_test

import (
	"testing"

	core "core-building-block/core"
	genmocks "core-building-block/mocks"
)

func TestAddListener(t *testing.T) {
	storage := genmocks.Storage{}
	core.NewApplication("1.1.1", "build", &storage, nil)
	/*
		listeners := app.listeners
		if len(listeners) != 0 {
			t.Error("listeners is not empty")
		}
	*/
	/*	app.AddListener(ListenerMock{})

		listeners = app.listeners
		if len(listeners) != 1 {
			t.Error("listeners must has 1 listener")
		} */
}
