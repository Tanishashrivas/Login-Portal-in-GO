package utils

type Login struct {
	HashedPassword string
	SessionToken   string
	CsrfToken      string
}

// fake db
var Users = map[string]Login{}