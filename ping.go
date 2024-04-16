package ldap4gin

import (
	"context"
)

// Ping ensures connection to ldap server is responding
func (a *Authenticator) Ping(_ context.Context) (err error) {
	_, err = a.LDAPConn.WhoAmI(nil)
	return
}
