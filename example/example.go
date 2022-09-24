package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

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
		ReadonlyDN:       "cn=readonly,dc=vodolaz095,dc=life",
		ReadonlyPasswd:   "readonly",
		TLS:              &tls.Config{}, // nearly sane default values
		StartTLS:         false,

		UserBaseTpl: "uid=%s,ou=people,dc=vodolaz095,dc=life",
		ExtraFields: []string{"l"}, // get location too

		ExtractGroups: true,
		GroupsOU:      "ou=groups,dc=vodolaz095,dc=life",

		TTL: 10 * time.Second,
	})
	if err != nil {
		log.Fatalf("%s : while initializing ldap4gin authenticator", err)
	}
	log.Println("LDAP server dialed!")
	defer authenticator.Close()
	// Application should use any of compatible sessions offered by
	// https://github.com/gin-contrib/sessions module
	// CAUTION: secure cookie session storage has limits on user profile size!!!
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
			c.Redirect(http.StatusFound, "/")
		} else {
			log.Printf("User %s authorized from %s!", username, c.ClientIP())
			session.AddFlash(fmt.Sprintf("Welcome, %s!", username))
		}
		user, err := authenticator.Extract(c)
		if err != nil {
			log.Printf("%s : while extracting user", err)
		} else {
			log.Printf("user %s is extracted", user.DN)
		}
		c.Redirect(http.StatusFound, "/")
	})

	// page to list groups
	r.GET("/groups", func(c *gin.Context) {
		session := sessions.Default(c)
		flashes := session.Flashes()
		user, err := authenticator.Extract(c)
		if err != nil {
			session.AddFlash(fmt.Sprintf("Authorization error  %s", err))
			c.Redirect(http.StatusFound, "/")
			return
		}
		session.Save()
		c.HTML(http.StatusOK, "groups.html", gin.H{
			"user":    user,
			"flashes": flashes,
		})
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
