package ldap4gin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// MetadataKeyName names key used to store user profile in request metadata
const MetadataKeyName = "ldap4gin_meta"

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

// LogDebugFunc used to define requirements for logging function
type LogDebugFunc func(ctx context.Context, format string, a ...any)

// DefaultLogDebugFunc is used for logging by default
var DefaultLogDebugFunc = func(ctx context.Context, format string, a ...any) {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().HasTraceID() {
		log.Default().Printf("ldap4gin ["+span.SpanContext().TraceID().String()+"]: "+format+"\n", a...)
	} else {
		log.Default().Printf("ldap4gin: "+format+"\n", a...)
	}
}

// Authenticator links ldap and gin context together
type Authenticator struct {
	// Options are runtime options as received from New
	Options *Options
	// LDAPConn is ldap connection being used
	LDAPConn *ldap.Conn
	// LogDebugFunc is function to log debug information
	LogDebugFunc LogDebugFunc

	currentBind string
	mu          *sync.Mutex
	fields      []string
}

func (a *Authenticator) debug(ctx context.Context, format string, data ...any) {
	if a.Options.Debug {
		a.LogDebugFunc(ctx, format, data...)
	}
}

func (a *Authenticator) bindAsUser(initialCtx context.Context, username, password string) (user *User, err error) {
	ctx, span := otel.Tracer("github.com/vodolaz095/ldap4gin").Start(initialCtx, "ldap4gin.bindAsUser",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()
	if !usernameRegexp.MatchString(username) {
		span.AddEvent("username malformed")
		err = ErrMalformed
		return
	}
	err = a.Ping(ctx)
	if err != nil {
		return nil, err
	}
	dn := fmt.Sprintf(a.Options.UserBaseTpl, username)
	span.SetAttributes(attribute.String("bind.dn", dn))
	span.AddEvent("preparing to bind as target user...")
	err = a.LDAPConn.Bind(dn, password)
	if err != nil {
		// if we had lost ldap connection and have something like this
		// `LDAP Result Code 200 "Network Error": ldap: connection closed"`
		// we redial connection and bind one more time
		if strings.Contains(err.Error(), "LDAP Result Code 200") {
			span.AddEvent("ldap connection is lost, restoring...")
			conn, err1 := ldap.DialURL(a.Options.ConnectionString, ldap.DialWithTLSConfig(a.Options.TLS))
			if err1 != nil {
				return nil, err1
			}
			if a.Options.StartTLS {
				span.AddEvent("starting tls...")
				err1 = conn.StartTLS(a.Options.TLS)
				if err1 != nil {
					return nil, err1
				}
			}
			a.LDAPConn = conn
			span.AddEvent("connection established, binding one more time...")
			err1 = a.LDAPConn.Bind(dn, password)
			if err1 != nil {
				if strings.Contains(err1.Error(), "LDAP Result Code 49") {
					span.AddEvent("invalid credentials")
					err = ErrInvalidCredentials
					return
				}
				// unexpected error
				span.RecordError(err1)
				span.SetStatus(codes.Error, err1.Error())
				return
			}
		}
		// wrong credentials
		if strings.Contains(err.Error(), "LDAP Result Code 49") {
			span.AddEvent("invalid credentials")
			err = ErrInvalidCredentials
			return
		}
		// unexpected error
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	a.currentBind = dn
	a.debug(ctx, "bind succeeded as %s", dn)
	span.AddEvent("bind succeeded")

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
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	if a.Options.Debug {
		res.PrettyPrint(2)
	}
	if len(res.Entries) == 0 {
		a.debug(ctx, "no user profile found for %s", username)
		span.AddEvent("no user profile found")
		err = ErrNotFound
		return
	}
	if len(res.Entries) > 1 {
		a.debug(ctx, "multiple user profile found for %s", username)
		span.AddEvent("multiple accounts found")
		err = ErrMultipleAccount
		return
	}
	span.AddEvent("user's profile found")
	a.debug(ctx, "user's profile found for %s", username)
	user, err = loadUserFromEntry(res.Entries[0])
	return
}

func (a *Authenticator) attachGroups(initialCtx context.Context, user *User) (err error) {
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
	ctx, span := otel.Tracer("github.com/vodolaz095/ldap4gin").
		Start(initialCtx, "ldap4gin:attachGroups",
			trace.WithSpanKind(trace.SpanKindClient),
		)
	defer span.End()
	span.AddEvent("binding as readonly")
	span.SetAttributes(attribute.String("bind.readonly_dn", a.Options.ReadonlyDN))
	span.SetAttributes(semconv.EnduserID(user.DN))
	err = a.Ping(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	if a.currentBind != a.Options.ReadonlyDN {
		err = a.LDAPConn.Bind(a.Options.ReadonlyDN, a.Options.ReadonlyPasswd)
		if err != nil {
			if strings.Contains(err.Error(), "LDAP Result Code 49") {
				span.AddEvent("invalid credentials for readonly user")
				err = ErrReadonlyWrongCredentials
				return
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return
		}
		a.currentBind = a.Options.ReadonlyDN
	}
	span.AddEvent("bound properly as readonly")
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
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	span.AddEvent("groups found")
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
		a.debug(ctx, "user %s is member of %s %s %s",
			groups[i].GID, groups[i].Name, groups[i].Description, user.UID)
	}
	span.AddEvent("groups parsed and attached")
	user.Groups = groups
	span.SetAttributes(semconv.EnduserRole(user.PrintGroups()))
	return
}

func (a *Authenticator) reload(initialCtx context.Context, user *User) (err error) {
	if a.Options.ReadonlyDN == "" {
		err = fmt.Errorf("readonly distinguished name is not configured")
		return
	}
	if a.Options.ReadonlyPasswd == "" {
		err = fmt.Errorf("readonlyPassword password is not set")
		return
	}
	ctx, span := otel.Tracer("github.com/vodolaz095/ldap4gin").Start(initialCtx, "ldap4gin.reload",
		trace.WithSpanKind(trace.SpanKindClient),
	)
	defer span.End()
	span.AddEvent("Binding as readonly...")
	err = a.Ping(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	if a.currentBind != a.Options.ReadonlyDN {
		err = a.LDAPConn.Bind(a.Options.ReadonlyDN, a.Options.ReadonlyPasswd)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return
		}
		a.currentBind = a.Options.ReadonlyDN
	}
	span.AddEvent("Searching user profile")
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
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	if a.Options.Debug {
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
	span.AddEvent("user profile is found")
	user, err = loadUserFromEntry(res.Entries[0])
	if err != nil {
		return
	}
	if a.Options.TTL > 0 {
		user.ExpiresAt = time.Now().Add(a.Options.TTL)
		a.debug(ctx, "set user %s to expire on %s",
			user.UID,
			user.ExpiresAt.Format("15:04:05"),
		)
	}
	if a.Options.ExtractGroups {
		err = a.attachGroups(ctx, user)
		if err != nil {
			return
		}
	}
	span.AddEvent("user profile is reloaded from ldap")
	a.debug(ctx, "user %s profile is reloaded from ldap", user.UID)
	return
}

// Authorize tries to find user in ldap database, check his/her password via `bind` and populate session, if password matches
func (a *Authenticator) Authorize(c *gin.Context, username, password string) (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	span := trace.SpanFromContext(c.Request.Context())
	session := sessions.Default(c)
	span.SetAttributes(attribute.String("username.raw", username))
	span.AddEvent("Binding to ldap...")
	user, err := a.bindAsUser(c.Request.Context(), username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			span.AddEvent("wrong credentials")
		} else {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
		}
		return
	}
	span.AddEvent("credentials accepted")
	span.SetAttributes(semconv.EnduserID(user.DN))
	if a.Options.ExtractGroups {
		span.AddEvent("Loading groups...")
		err = a.attachGroups(c.Request.Context(), user)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return
		}
		span.SetAttributes(semconv.EnduserRole(user.PrintGroups()))
	}
	if a.Options.TTL > 0 {
		user.ExpiresAt = time.Now().Add(a.Options.TTL)
	}
	session.Set(SessionKeyName, user)
	span.AddEvent("user authorized properly")
	err = session.Save()
	return
}

// Extract extracts users profile from session
func (a *Authenticator) Extract(c *gin.Context) (user *User, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	span := trace.SpanFromContext(c.Request.Context())
	userFromMeta, found := c.Get(MetadataKeyName)
	if found {
		span.AddEvent("user profile extracted from metadata")
		return userFromMeta.(*User), nil
	}
	span.AddEvent("extracting user profile from session")
	session := sessions.Default(c)
	ui := session.Get(SessionKeyName)
	if ui != nil {
		switch ui.(type) {
		case User:
			raw := ui.(User)
			user = &raw
			break
		case *User:
			user = ui.(*User)
		default:
			err = fmt.Errorf("unknown type")
			return
		}
		span.AddEvent("User extracted from session")
		a.debug(c.Request.Context(),
			"user %s is extracted from session of %v using %s",
			user.UID, c.ClientIP(), c.GetHeader("User-Agent"))

		if user.Expired() {
			span.AddEvent("User session expired")
			a.debug(c.Request.Context(), "user's profile %s expired on %s %s ago, refreshing...",
				user.UID, user.ExpiresAt.Format(time.Stamp),
				time.Now().Sub(user.ExpiresAt).String(),
			)
			err = a.reload(c.Request.Context(), user)
			if err != nil {
				return
			}
			span.AddEvent("User session is reloaded")
			user.ExpiresAt = time.Now().Add(a.Options.TTL)
		} else {
			span.AddEvent("User session is valid")
			a.debug(c.Request.Context(), "user's profile %s is valid until %s for %s",
				user.UID, user.ExpiresAt.Format(time.Stamp),
				user.ExpiresAt.Sub(time.Now()).String(),
			)
		}
		span.SetAttributes(semconv.EnduserID(user.DN))
		span.SetAttributes(semconv.EnduserRole(user.PrintGroups()))
		session.Set(SessionKeyName, *user)
		c.Set(MetadataKeyName, user)
		err = session.Save()
	} else {
		span.AddEvent("user session is not found")
		err = ErrUnauthorized
	}
	return
}

// Logout terminates user's session
func (a *Authenticator) Logout(c *gin.Context) error {
	session := sessions.Default(c)
	session.Delete(SessionKeyName)
	return session.Save()
}

// Close closes authenticator connection to ldap
func (a *Authenticator) Close() error {
	return a.LDAPConn.Unbind()
}
