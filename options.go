package ldap4gin

import (
	"crypto/tls"
	"time"
)

// Options depicts parameters used to instantiate Authenticator
type Options struct {
	// Debug outputs debugging information, better leave it to false
	Debug bool

	// TTL depicts how long user profile is cached in session, when it expires, it is reloaded from ldap
	TTL time.Duration

	/*
		Define how we connect to LDAP
	*/

	//ConnectionString depicts how we dial LDAP server, something like ldap://127.0.0.1:389 or ldaps://ldap.example.org:636
	ConnectionString string
	// TLS is configuration for encryption to use
	TLS *tls.Config
	// StartTLS shows, do we need to execute StartTLS or not
	StartTLS bool

	/*
		Define how we authorize as readonly user
		against LDAP
	*/

	// ReadonlyDN is distinguished name used for authorization as readonly user,
	// who has access to listing groups of user. For example, "cn=readonly,dc=vodolaz095,dc=ru"
	ReadonlyDN string
	// ReadonlyPasswd is password for readonly user, who has access to listing groups
	ReadonlyPasswd string

	/*
	  Used for extracting users
	*/

	// UserBaseTpl is template to extract user profiles by UID, for example
	// "uid=%s,ou=people,dc=vodolaz095,dc=ru" or
	// "email=%s,ou=people,dc=vodolaz095,dc=ru"
	UserBaseTpl string
	// ExtraFields is array of fields, we also extract from database.
	// NOTICE - if you add too many fields, it can hit session size limits!
	ExtraFields []string

	// ExtractGroups toggles extracting groups of user
	ExtractGroups bool
	// GroupsOU depicts organization unit for groups, usually "ou=groups,dc=vodolaz095,dc=ru"
	GroupsOU string

	// LogDebugFunc is called to log debug events
	LogDebugFunc LogDebugFunc
}
