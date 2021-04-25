package ldap4gin

import (
	"crypto/tls"
	ldap "github.com/go-ldap/ldap/v3"
)

// Options depicts parameters
type Options struct {
	Debug            bool
	ConnectionString string
	UserBaseTpl      string //
	TLS              *tls.Config
	StartTLS         bool
}

type Authenticator struct {
	debug       bool
	UserBaseTpl string
	LDAPConn    *ldap.Conn
}

func New(opts Options) (a *Authenticator, err error) {
	if opts.TLS != nil {

	} else {
		opts.TLS = &tls.Config{}
	}
	a.debug = opts.Debug
	a.UserBaseTpl = opts.UserBaseTpl
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
	return
}
