package core

func (app *Application) serGetVersion() string {
	return app.version
}

func (app *Application) serGetAuthTest() string {
	return "Services - Auth - test"
}

func (app *Application) serGetCommonTest() string {
	return "Services - Common - test"
}
