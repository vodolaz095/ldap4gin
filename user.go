package ldap4gin

import (
	"encoding/gob"
	"github.com/go-ldap/ldap/v3"
)

// User depicts profile of authorized user
type User struct {
	// General
	DN  string // dn: uid=sveta,ou=people,dc=vodolaz095,dc=life
	UID string //uid: sveta

	// Names
	GivenName  string // `givenname` - Svetlana
	CommonName string // `cn` - Svetlana Belaya
	Initials   string // `initials` - SA
	Surname    string // `sn` - Belaya

	// work specific
	Organization     string // o: R&D
	OrganizationUnit string // Laboratory 47
	Title            string // title: developer
	Description      string // description: writes code

	// Internet related
	Website string   // labeleduri: https://vodolaz095.life
	Emails  []string // `mail` user can have few emails

	// Linux specific
	UIDNumber     uint64 // uidnumber 1000
	GIDNumber     uint64 // gidnumber 1000
	HomeDirectory string // homedirectory: /home/sveta
	LoginShell    string // loginshell - /bin/bash

	// Raw entry extracted from LDAP
	Entry *ldap.Entry
}

// GetDefaultFields returns fields we extract from LDAP by default
func GetDefaultFields() []string {
	return []string{
		"dn",
		"uid",

		"givenName",
		"cn",
		"initials",
		"sn",

		"o",
		"ou",
		"title",
		"description",

		"labeledURI",
		"mail",

		"uidNumber",
		"gidNumber",
		"homeDirectory",
		"loginShell",
	}
}

func init() {
	gob.Register(User{})
}
