# ldap4gin
Authenticator for gin framework using ldap server

[![Go Report Card](https://goreportcard.com/badge/github.com/vodolaz095/ldap4gin)](https://goreportcard.com/report/github.com/vodolaz095/ldap4gin)
[![GoDoc](https://godoc.org/github.com/vodolaz095/ldap4gin?status.svg)](https://godoc.org/github.com/vodolaz095/ldap4gin)


# Advertisement
You can support development of this module by sending me money directly
https://www.tinkoff.ru/rm/ostroumov.anatoliy2/4HFzm76801/

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
   authenticator, err := ldap4gin.New(&ldap4gin.Options{
      Debug: gin.IsDebugging(),

      ConnectionString: "ldap://127.0.0.1:389",
      ReadonlyDN:       "cn=readonly,dc=vodolaz095,dc=life", // only required, if we enable ExtractGroups:true
      ReadonlyPasswd:   "readonly",  // only required, if we enable ExtractGroups:true
      TLS:              &tls.Config{}, // nearly sane default values
      StartTLS:         false,

      UserBaseTpl: "uid=%s,ou=people,dc=vodolaz095,dc=life",
      ExtraFields: []string{"l"}, // get location too

      ExtractGroups: true, 
      GroupsOU:      "ou=groups,dc=vodolaz095,dc=life",  // only required, if we enable ExtractGroups:true

      // how long to store user's profile in session, 
      // if profile is expired, it is reloaded from ldap database
	  // if we set TTL to 0, profile will never expire
      TTL: 10 * time.Second, 
   })
   if err != nil {
      log.Fatalf("%s : while initializing ldap4gin authenticator", err)
   }
   log.Println("LDAP server dialed!")
   defer authenticator.Close()

   // Application should use any of compatible sessions offered by
   // https://github.com/gin-contrib/sessions module
   // CAUTION:  secure cookie session storage has limits on user profile size!!!
   store := cookie.NewStore([]byte("secret"))
   r.Use(sessions.Sessions("mysession", store))

   // dashboard
   r.GET("/", func(c *gin.Context) {
      session := sessions.Default(c)
      flashes := session.Flashes()
      //  extracting user's profile from context
      user, err := authenticator.Extract(c)
      if err != nil {
         if err.Error() == "unauthorized" { // render login page
            session.AddFlash("Authorization failed")
            session.Save()
            c.HTML(http.StatusUnauthorized, "unauthorized.html", gin.H{
               "flashes": flashes,
            })
            return
         }
         if err.Error() == "malformed username" {
            session.AddFlash("Malformed username")
            session.Save()
            c.HTML(http.StatusUnauthorized, "unauthorized.html", gin.H{
               "flashes": flashes,
            })
            return
         }
         panic(err) // something wrong, like LDAP server stopped
      }
      // We can extract extra attributes for user using `user.Entry`
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

   // route to authorize user by username and password
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

   // route to terminate session and perform logout
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

You can read [very good article in Russian language describing authentication process via LDAP](https://vodolaz095.ru/nodejs-openldap/).

Shortly, these steps are performed in this module module:

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

5. If we enable extraction of groups by setting  `ExtractGroups:true`, we will also perform bind by specual user
   with readonly access to all database in order to load groups of user we want to authenticate

# MIT License

Copyright (c) 2021 Anatolij Ostroumov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
