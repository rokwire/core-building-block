package storage

import "time"

type applicationGroup struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	AppID string `bson:"app_id"`

	Permissions []applicationPermission `bson:"permissions"`
	Roles       []applicationRole       `bson:"roles"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationRole struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`

	AppID string `bson:"app_id"`

	Permissions []applicationPermission `bson:"permissions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationPermission struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	AppID string `bson:"app_id"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
