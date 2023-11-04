package ldap4gin

import (
	"encoding/gob"
	"regexp"
)

func init() {
	gob.Register(User{})
	gob.Register(Group{})
	// https://unix.stackexchange.com/a/435120/229266
	usernameRegexp = regexp.MustCompile("^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\\$)$")
}
