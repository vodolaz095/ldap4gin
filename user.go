package ldap4gin

// User depicts authorized user
type User struct {
	DN  string // dn: uid=sveta,ou=people,dc=vodolaz095,dc=life
	UID string //uid: sveta

	// Names
	GivenName   string   // `givenname` - Svetlana
	CommonName  string   // `cn` - Svetlana Belaya
	Initials    string   // `initials` - SA
	Surname     string   // `sn` - Belaya
	Description string   // description
	Title       string   // `title`, developer
	Emails      []string // `mail` user can have few emails

	// Linux specific
	UIDNumber     uint64 // uidnumber 1000
	GIDNumber     uint64 // gidnumber 1000
	HomeDirectory string // homedirectory: /home/sveta
	LoginShell    string // loginshell - /bin/bash
}

// Fields are fields of user profile we load from database, can be altered
var Fields = []string{
	"dn",
	"uid",

	"givenname",
	"cn",
	"initials",
	"sn",
	"description",
	"title",
	"email",

	"uidNumber",
	"gidNumber",
	"homedirectory",
	"loginshell",
}
