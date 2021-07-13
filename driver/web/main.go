package web

type organization struct {
	Id string `json:"id"`

	Name string `json:"name"`

	Type_ string `json:"type"`

	RequiresOwnLogin bool `json:"requires-own-login,omitempty"`

	LoginTypes []string `json:"login-types,omitempty"`

	Config *organizationConfig `json:"config,omitempty"`
}

type organizationConfig struct {
	// organization config id
	Id string `json:"id,omitempty"`
	// organization domains
	Domains []string `json:"domains,omitempty"`
}
