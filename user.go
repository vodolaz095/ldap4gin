package ldap4gin

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"regexp"
	"strconv"
	"time"
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
	OrganizationUnit string // ou: Laboratory 47
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

	// groups
	Groups []Group

	// Raw entry extracted from LDAP
	Entry     *ldap.Entry
	ExpiresAt time.Time
}

// Expired returns true, if user profile should be reloaded from ldap database
func (u *User) Expired() bool {
	if u.ExpiresAt.IsZero() {
		return false
	}
	return u.ExpiresAt.Before(time.Now())
}

// HasGroupByGID checks, if user is a member of group with this GID
func (u *User) HasGroupByGID(gid string) (ok bool) {
	for i := range u.Groups {
		if ok {
			break
		}
		ok = u.Groups[i].GID == gid
	}
	return
}

// HasGroupByName checks, if user is a member of group with this name
func (u *User) HasGroupByName(name string) (ok bool) {
	for i := range u.Groups {
		if ok {
			break
		}
		ok = u.Groups[i].GID == name
	}
	return
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

func loadUserFromEntry(entry *ldap.Entry) (user *User, err error) {
	user = &User{
		DN:  entry.DN,
		UID: entry.GetAttributeValue("uid"),

		Initials: entry.GetAttributeValue("initials"),

		GivenName:  entry.GetAttributeValue("givenName"),
		CommonName: entry.GetAttributeValue("cn"),
		Surname:    entry.GetAttributeValue("sn"),

		Organization:     entry.GetAttributeValue("o"),
		OrganizationUnit: entry.GetAttributeValue("ou"),
		Description:      entry.GetAttributeValue("description"),
		Title:            entry.GetAttributeValue("title"),

		Website: entry.GetAttributeValue("labeledURI"),

		HomeDirectory: entry.GetAttributeValue("homeDirectory"),
		LoginShell:    entry.GetAttributeValue("loginShell"),
		Entry:         entry,
	}
	var gidAsInt, uidAsInt uint64

	uid := entry.GetAttributeValue("uidNumber")
	if uid != "" {
		uidAsInt, err = strconv.ParseUint(uid, 10, 32)
		if err != nil {
			err = fmt.Errorf("%s : while parsing uidNumber %s of user %s", err, uid, user.DN)
			return
		}
		user.UIDNumber = uidAsInt
	}

	gid := entry.GetAttributeValue("gidNumber")
	if gid != "" {
		gidAsInt, err = strconv.ParseUint(uid, 10, 32)
		if err != nil {
			err = fmt.Errorf("%s : while parsing gidNumber %s of user %s", err, gid, user.DN)
			return
		}
		user.GIDNumber = gidAsInt
	}
	emails := entry.GetRawAttributeValues("mail")
	for _, email := range emails {
		user.Emails = append(user.Emails, string(email))
	}
	return
}

var usernameRegexp *regexp.Regexp
