package ldap4gin

import (
	"github.com/go-ldap/ldap/v3"
)

// New creates new authenticator using options provided
func New(opts *Options) (a *Authenticator, err error) {
	a = &Authenticator{
		Options: opts,
	}
	a.fields = GetDefaultFields()
	a.fields = append(a.fields, opts.ExtraFields...)
	conn, err := ldap.DialURL(opts.ConnectionString, ldap.DialWithTLSConfig(opts.TLS))
	if err != nil {
		return
	}
	if opts.StartTLS {
		err = conn.StartTLS(opts.TLS)
		if err != nil {
			return
		}
	}
	a.LDAPConn = conn
	if opts.LogDebugFunc != nil {
		a.LogDebugFunc = opts.LogDebugFunc
	} else {
		a.LogDebugFunc = DefaultLogDebugFunc
	}
	return
}
