package ldap4gin

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
)

// SessionKeyName names key used to store user profile in session
const SessionKeyName = "ldap4gin_user"

func timeOut(ctx context.Context) (timeout int) {
	deadline, ok := ctx.Deadline()
	if ok {
		timeout = int(math.Round(deadline.Sub(time.Now()).Seconds()))
	} else {
		timeout = 0
	}
	return
}

// Authenticator links ldap and gin context together
type Authenticator struct {
	fields []string
	// Options are runtime options as received from New
	Options *Options
	// LDAPConn is ldap connection being used
	LDAPConn *ldap.Conn
}

func (a *Authenticator) bindAsUser(ctx context.Context, username, password string) (user *User, err error) {
	if !usernameRegexp.MatchString(username) {
		err = ErrMalformed
		return
	}
	dn := fmt.Sprintf(a.Options.UserBaseTpl, username)
	err = a.LDAPConn.Bind(dn, password)
	if err != nil {
		if strings.Contains(err.Error(), "LDAP Result Code 49") {
			err = ErrInvalidCredentials
			return
		}
		return
	}
	// Search info about given username
	timeout := timeOut(ctx)
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
	if a.Options.Debug {
		fmt.Println("ldap4gin: user profile found")
		res.PrettyPrint(2)
	}
	if len(res.Entries) == 0 {
		err = ErrNotFound
		return
	}
	if len(res.Entries) > 1 {
		err = ErrMultipleAccount
		return
	}
	user, err = loadUserFromEntry(res.Entries[0])
	return
}

func (a *Authenticator) attachGroups(ctx context.Context, user *User) (err error) {
	if a.Options.GroupsOU == "" {
		err = fmt.Errorf("groups organization unit is not configured")
		return
	}
	if a.Options.ReadonlyDN == "" {
		err = fmt.Errorf("readonly distinguished name is not configured")
		return
	}
	if a.Options.ReadonlyPasswd == "" {
		err = fmt.Errorf("readonlyPassword password is not set")
		return
	}
	err = a.LDAPConn.Bind(a.Options.ReadonlyDN, a.Options.ReadonlyPasswd)
	if err != nil {
		if strings.Contains(err.Error(), "LDAP Result Code 49") {
			err = ErrReadonlyWrongCredentials
			return
		}
		return
	}
	searchGroupsRequest := ldap.NewSearchRequest(
		a.Options.GroupsOU,     // base DN
		ldap.ScopeWholeSubtree, // scope
		ldap.DerefAlways,       // DerefAliases
		0,                      // size limit
		timeOut(ctx),           // timeout
		false,                  // types only
		fmt.Sprintf("(&(memberUid=%s))", user.UID), // filter
		defaultGroupFields,                         // fields
		nil,                                        // controls
	)
	res, err := a.LDAPConn.Search(searchGroupsRequest)
	if err != nil {
		return
	}
	if a.Options.Debug {
		res.PrettyPrint(2)
	}
	groups := make([]Group, len(res.Entries))
	for i := range res.Entries {
		groups[i] = Group{
			GID:         res.Entries[i].GetAttributeValue("gidNumber"),
			Name:        res.Entries[i].GetAttributeValue("cn"),
			Description: res.Entries[i].GetAttributeValue("description"),
		}
	}
	user.Groups = groups
	return
}

func (a *Authenticator) reload(ctx context.Context, user *User) (err error) {
	if !user.Expired() {
		if a.Options.Debug {
			fmt.Printf("ldap4gin: user %s will expire in %s\n",
				user.UID, user.ExpiresAt.Sub(time.Now()).String())
		}
		return nil
	}
	if a.Options.Debug {
		fmt.Printf("ldap4gin: user %s expired\n", user.UID)
	}
	if a.Options.ReadonlyDN == "" {
		err = fmt.Errorf("readonly distinguished name is not configured")
		return
	}
	if a.Options.ReadonlyPasswd == "" {
		err = fmt.Errorf("readonlyPassword password is not set")
		return
	}
	err = a.LDAPConn.Bind(a.Options.ReadonlyDN, a.Options.ReadonlyPasswd)
	if err != nil {
		return
	}
	searchRequest := ldap.NewSearchRequest(
		user.DN,                           // base DN
		ldap.ScopeBaseObject,              // scope
		ldap.NeverDerefAliases,            // DerefAliases
		0,                                 // size limit
		timeOut(ctx),                      // timeout
		false,                             // types only
		fmt.Sprintf("(uid=%s)", user.UID), // filter
		a.fields,                          // fields
		nil,                               // controls
	)
	res, err := a.LDAPConn.Search(searchRequest)
	if err != nil {
		return
	}
	if a.Options.Debug {
		fmt.Println("ldap4gin: user profile found")
		res.PrettyPrint(2)
	}
	if len(res.Entries) == 0 {
		err = ErrNotFound
		return
	}
	if len(res.Entries) > 1 {
		err = ErrMultipleAccount
		return
	}
	user, err = loadUserFromEntry(res.Entries[0])
	if err != nil {
		return
	}
	if a.Options.ExtractGroups {
		err = a.attachGroups(ctx, user)
	}
	return
}

// Authorize tries to find user in ldap database, check his/her password via `bind` and populate session, if password matches
func (a *Authenticator) Authorize(c *gin.Context, username, password string) (err error) {
	session := sessions.Default(c)
	user, err := a.bindAsUser(c.Request.Context(), username, password)
	if err != nil {
		return
	}
	if a.Options.ExtractGroups {
		err = a.attachGroups(c.Request.Context(), user)
		if err != nil {
			return
		}
	}
	if a.Options.TTL > 0 {
		user.ExpiresAt = time.Now().Add(a.Options.TTL)
	}
	session.Set(SessionKeyName, &user)
	err = session.Save()
	return
}

// Extract extracts users profile from session
func (a *Authenticator) Extract(c *gin.Context) (user User, err error) {
	session := sessions.Default(c)
	ui := session.Get(SessionKeyName)
	if ui != nil {
		user = ui.(User)
		if a.Options.Debug {
			fmt.Printf("ldap4gin: user %s is extracted from session of %v using %s\n",
				user.UID, c.ClientIP(), c.GetHeader("User-Agent"))
		}
		err = a.reload(c.Request.Context(), &user)
	} else {
		err = ErrUnauthorized
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

// Close closes authenticator connection to ldap
func (a *Authenticator) Close() (err error) {
	err = a.LDAPConn.Unbind()
	return
}
