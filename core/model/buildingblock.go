package model

//BuildingBlock represents building block entity
type BuildingBlock struct {
	Key          string                     `json:"key" bson:"_id"`
	Name         string                     `json:"name" bson:"name"`
	VersionURL   *string                    `json:"version_url" bson:"version_url"`
	Environments []BuildingBlockEnvironment `json:"environments" bson:"environments"`
}

//BuildingBlockEnvironment represents building block environment entity
type BuildingBlockEnvironment struct {
	Key          string  `json:"key" bson:"key"`
	HealthStatus string  `json:"health_status" bson:"health_status"`
	Version      string  `json:"version" bson:"version"`
	ApisURL      *string `json:"apis_url" bson:"apis_url"`
	WebURL       *string `json:"web_url" bson:"web_url"`
}
