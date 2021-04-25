package ldap4gin

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

// SessionKeyName names key used to store user profile in session
const SessionKeyName = "ldap4gin_user"

// Authorize tries to find user in ldap database, check his/her password via `bind` and populate session, if password matches
func (a *Authenticator) Authorize(c *gin.Context, username, password string) (err error) {
	session := sessions.Default(c)
	dn := fmt.Sprintf(a.userBaseTpl, username)
	err = a.LDAPConn.Bind(dn, password)
	if err != nil {
		if strings.HasPrefix("LDAP Result Code 49 \"Invalid Credentials\"", err.Error()) {
			err = fmt.Errorf("invalid credentials")
			return
		}
		return
	}
	// Search info about given username
	var timeout int
	deadline, ok := c.Request.Context().Deadline()
	if ok {
		timeout = int(math.Round(deadline.Sub(time.Now()).Seconds()))
	} else {
		timeout = 0
	}
	searchRequest := ldap.NewSearchRequest(
		dn,                                // base DN
		ldap.ScopeBaseObject,              // scope
		ldap.NeverDerefAliases,            // DerefAliases
		0,                                 // size limit
		timeout,                           // timeout
		false,                             // types only
		fmt.Sprintf("(uid=%s)", username), // filter
		a.fields,                          // fields
		nil,                               // controls
	)
	res, err := a.LDAPConn.Search(searchRequest)
	if err != nil {
		return
	}
	if a.debug {
		fmt.Println("ldap4gin: user profile found")
		res.PrettyPrint(2)
	}
	if len(res.Entries) == 0 {
		err = fmt.Errorf("user not found")
		return
	}
	if len(res.Entries) > 1 {
		err = fmt.Errorf("multiple user profiles found")
		return
	}
	entry := res.Entries[0]
	user := User{
		DN:         entry.DN,
		UID:        entry.GetAttributeValue("uid"),
		GivenName:  entry.GetAttributeValue("givenName"),
		CommonName: entry.GetAttributeValue("cn"),
		Initials:   entry.GetAttributeValue("initials"),
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
	uid := entry.GetAttributeValue("uidNumber")
	if uid != "" {
		uidAsInt, err := strconv.ParseUint(uid, 10, 32)
		if err != nil {
			return fmt.Errorf("%s : while parsing uidNumber %s of user %s", err, uid, user.DN)
		}
		user.UIDNumber = uidAsInt
	}

	gid := entry.GetAttributeValue("gidNumber")
	if gid != "" {
		gidAsInt, err := strconv.ParseUint(uid, 10, 32)
		if err != nil {
			return fmt.Errorf("%s : while parsing gidNumber %s of user %s", err, gid, user.DN)
		}
		user.GIDNumber = gidAsInt
	}
	emails := entry.GetRawAttributeValues("mail")
	for _, email := range emails {
		user.Emails = append(user.Emails, string(email))
	}
	session.Set(SessionKeyName, user)
	err = session.Save()
	return
}

// Extract extracts users profile from session
func (a *Authenticator) Extract(c *gin.Context) (user User, err error) {
	session := sessions.Default(c)
	ui := session.Get(SessionKeyName)
	if ui != nil {
		user = ui.(User)
		fmt.Println(user)
	} else {
		err = fmt.Errorf("unauthorized")
	}
	return
}

// Logout terminates user's session
func (a *Authenticator) Logout(c *gin.Context) (err error) {
	session := sessions.Default(c)
	session.Delete(SessionKeyName)
	err = session.Save()
	return
}
