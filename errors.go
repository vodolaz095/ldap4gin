package ldap4gin

import "fmt"

var (
	// ErrUnauthorized means the user is not authorized to access the resource
	ErrUnauthorized = fmt.Errorf("unauthorized")
	// ErrMalformed means the username is not in the expected format
	ErrMalformed = fmt.Errorf("malformed username")
	// ErrInvalidCredentials means the user provided invalid credentials
	ErrInvalidCredentials = fmt.Errorf("invalid credentials")
	// ErrNotFound means the user was not found
	ErrNotFound = fmt.Errorf("user not found")
	// ErrMultipleAccount means multiple user profiles were found
	ErrMultipleAccount = fmt.Errorf("multiple user profiles found")
	// ErrReadonlyWrongCredentials means the readonly user has wrong credentials
	ErrReadonlyWrongCredentials = fmt.Errorf("readonly user has wrong credentials")
)
