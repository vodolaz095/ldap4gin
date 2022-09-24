package ldap4gin

import (
	"encoding/gob"
	"regexp"
)

func init() {
	gob.Register(User{})
	gob.Register(Group{})
	usernameRegexp = regexp.MustCompile("^[0-9A-Za-z_]+$")
}
