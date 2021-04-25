package main

import (
	"log"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/vodolaz095/ldap4gin"
)

func main() {
	r := gin.Default()
	authenticator, err := ldap4gin.New(ldap4gin.Options{
		Debug:            gin.IsDebugging(),
		ConnectionString: "ldap://127.0.0.1:389",
		UserBaseTpl:      "uid=%s,ou=people,dc=vodolaz095,dc=life",
		TLS:              nil,
		StartTLS:         false,
	})
	if err != nil {
		log.Fatalf("%s : while initializing ldap4gin authenticator", err)
	}
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/", func(c *gin.Context) {
		user, err := authenticator.Extract(c)
		if err != nil {
			if err.Error() == "unauthorized" {
				c.HTML(http.StatusUnauthorized, "unauthorized.html", nil)
				return
			}
			panic(err)
		}
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"user": user,
		})
	})

	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		err = authenticator.Authorize(c, username, password)

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
