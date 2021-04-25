package ldap4gin

import (
	"crypto/tls"
	"github.com/go-ldap/ldap/v3"
)

// Options depicts parameters used to instantiate Authenticator
type Options struct {
	// Debug outputs debugging information, better leave it to false
	Debug bool
	//ConnectionString depicts how we dial LDAP server, something like ldap://127.0.0.1:389 or ldaps://ldap.example.org:636
	ConnectionString string
	// UserBaseTpl is template to extract user profiles by UID, for example  "uid=%s,ou=people,dc=example,dc=org",
	UserBaseTpl string
	// TLS is configuration for encryption to use
	TLS *tls.Config
	// StartTLS shows, do we need to execute StartTLS or not
	StartTLS bool
	// ExtraFields is array of fields, we also extract from database. NOTICE - if you add too many fields, it can hit session size limits!
	ExtraFields []string
}

// Authenticator links ldap and gin context together
type Authenticator struct {
	debug       bool
	userBaseTpl string
	// LDAPConn is ldap connection being used
	LDAPConn *ldap.Conn
	fields   []string
}

// New creates new authenticator using options provided
func New(opts Options) (a *Authenticator, err error) {
	a = &Authenticator{
		debug:       opts.Debug,
		userBaseTpl: opts.UserBaseTpl,
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
	return
}
