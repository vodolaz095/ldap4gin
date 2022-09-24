package ldap4gin

import "fmt"

var (
	ErrUnauthorized             = fmt.Errorf("unauthorized")
	ErrMalformed                = fmt.Errorf("malformed username")
	ErrInvalidCredentials       = fmt.Errorf("invalid credentials")
	ErrNotFound                 = fmt.Errorf("user not found")
	ErrMultipleAccount          = fmt.Errorf("multiple user profiles found")
	ErrReadonlyWrongCredentials = fmt.Errorf("readonly user has wrong credentials")
)
