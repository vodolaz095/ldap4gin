# ldap4gin
Authenticator for gin framework using ldap server

[![Go Report Card](https://goreportcard.com/badge/github.com/vodolaz095/ldap4gin)](https://goreportcard.com/report/github.com/vodolaz095/ldap4gin)
[![GoDoc](https://godoc.org/github.com/vodolaz095/ldap4gin?status.svg)](https://godoc.org/github.com/vodolaz095/ldap4gin)

# Installing

Usual way for go module

```shell

go get -u github.com/vodolaz095/ldap4gin

```

Code was tested against popular [osixia/openldap:1.4.0](https://hub.docker.com/r/osixia/openldap) container,
with records generated using [ldapaccountmanager/lam](https://hub.docker.com/r/ldapaccountmanager/lam) web ui.

# Example
Working example is published in `example/` subdirectory of this repo

```go

package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/vodolaz095/ldap4gin"
)

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("views/*")
	// configuring options used to connect to LDAP database
	authenticator, err := ldap4gin.New(ldap4gin.Options{
		Debug:            gin.IsDebugging(),
		ConnectionString: "ldap://127.0.0.1:389",
		UserBaseTpl:      "uid=%s,ou=people,dc=vodolaz095,dc=life",
		TLS:              &tls.Config{}, // nearly sane default values
		StartTLS:         false,
		ExtraFields:      []string{"l"}, // get location too
	})
	if err != nil {
		log.Fatalf("%s : while initializing ldap4gin authenticator", err)
	}
	log.Println("LDAP server dialed!")
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/", func(c *gin.Context) {
		session := sessions.Default(c)
		flashes := session.Flashes()
		user, err := authenticator.Extract(c)
		if err != nil {
			if err.Error() == "unauthorized" {
				session.Save()
				c.HTML(http.StatusUnauthorized, "unauthorized.html", gin.H{
					"flashes": flashes,
				})
				return
			}
			panic(err)
		}
		buff := bytes.NewBuffer(nil)
		fmt.Fprintf(buff, "DN: %s\n", user.Entry.DN)
		for _, attr := range user.Entry.Attributes {
			fmt.Fprintf(buff, "%s: %s\n", attr.Name, attr.Values)
		}
		session.Save()
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"user":    user,
			"flashes": flashes,
			"raw":     buff.String(),
		})
	})

	r.POST("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		username := c.PostForm("username")
		password := c.PostForm("password")
		log.Printf("User %s tries to authorize from %s...", username, c.ClientIP())
		err := authenticator.Authorize(c, username, password)
		if err != nil {
			log.Printf("User %s failed to authorize from %s because of %s", username, c.ClientIP(), err.Error())
			session.AddFlash(fmt.Sprintf("Authorization error  %s", err))
		} else {
			log.Printf("User %s authorized from %s!", username, c.ClientIP())
			session.AddFlash(fmt.Sprintf("Welcome, %s!", username))
		}
		session.Save()
		c.Redirect(http.StatusFound, "/")
	})

	r.GET("/logout", func(c *gin.Context) {
		authenticator.Logout(c)
		c.Redirect(http.StatusFound, "/")
	})

	err = r.Run("0.0.0.0:3000")
	if err != nil {
		log.Fatalf("%s : while starting application", err)
	}
}



```

How it works?
============================

You can read [very good article in Russian language describing authentication process via LDAP](https://vodolaz095.life/nodejs-openldap/).

Shortly, these steps are performed in `authorize.go` module:

1. we build DN using `username` parameter provided and `UserBaseTpl` of options

```go
    
    authenticator, err := ldap4gin.New(ldap4gin.Options{
        Debug:            gin.IsDebugging(),
        ConnectionString: "ldap://127.0.0.1:389",
        UserBaseTpl:      "uid=%s,ou=people,dc=vodolaz095,dc=life",
        TLS:              &tls.Config{}, // nearly sane default values
        StartTLS:         false,
        ExtraFields:      []string{"l"}, // get location too
    })

    // some code

    // in gin handler
    err = authenticator.Authorize(c, username, password)

```

  like this: `uid=vodolaz095,ou=people,dc=vodolaz095,dc=life`.

2. we try to perform bind using `DN` and `password`

```go

    authenticator.LDAPConn.Bind(dn, password)

```

3. if we succeeded, it means user provided good password, and we can try to extract user profile calling this query:

```go

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


```

4. After we extract data, we marshal it in User object, and store it in session using `gob` encoding. Its is worth notice
   that sometimes profile size is too big for session storage, and it can be wise not to store all users fields in session
   



