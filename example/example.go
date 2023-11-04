package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/vodolaz095/ldap4gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func main() {
	// tracing
	hostname, err := os.Hostname()
	if err != nil {
		return
	}

	// export via compact thrift protocol over upd - important
	exp, err := jaeger.New(jaeger.WithAgentEndpoint(
		jaeger.WithAgentHost("127.0.0.1"),
		jaeger.WithAgentPort("6831"),
	))
	if err != nil {
		return
	}

	tp := tracesdk.NewTracerProvider(
		// Always be sure to batch in production.
		tracesdk.WithBatcher(exp),
		// sample 100% of data
		tracesdk.WithSampler(tracesdk.TraceIDRatioBased(1)),
		// Record information about this application in a Resource.
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("ldap4gin_example"),
			semconv.HostID(hostname),
		)),
	)
	// Register our TracerProvider as the global so any imported
	// instrumentation in the future will default to using it.
	otel.SetTracerProvider(tp)

	// setup gin application

	r := gin.Default()
	r.LoadHTMLGlob("views/*")
	r.Use(otelgin.Middleware("ldap4gin_example_gin_router",
		otelgin.WithSpanNameFormatter(func(r *http.Request) string {
			return r.Method + " " + r.URL.Path
		})))

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
		var cErr error
		session := sessions.Default(c)
		flashes := session.Flashes()
		defer session.Save()
		//  extracting user's profile from context
		user, cErr := authenticator.Extract(c)
		if cErr != nil {
			if cErr.Error() == "unauthorized" { // render login page
				c.HTML(http.StatusUnauthorized, "unauthorized.html", gin.H{
					"flashes": flashes,
				})
				return
			}
			if cErr.Error() == "malformed username" {
				session.AddFlash("Malformed username")
				c.HTML(http.StatusUnauthorized, "unauthorized.html", gin.H{
					"flashes": flashes,
				})
				return
			}
			panic(cErr) // something wrong, like LDAP server stopped
		}
		// We can extract extra attributes for user using `user.Entry`
		buff := bytes.NewBuffer(nil)
		fmt.Fprintf(buff, "DN: %s\n", user.Entry.DN)
		for _, attr := range user.Entry.Attributes {
			fmt.Fprintf(buff, "%s: %s\n", attr.Name, attr.Values)
		}
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"user":    user,
			"flashes": flashes,
			"raw":     buff.String(),
		})
	})

	// route to authorize user by username and password
	r.POST("/login", func(c *gin.Context) {
		var cErr error
		session := sessions.Default(c)
		defer session.Save()
		username := c.PostForm("username")
		password := c.PostForm("password")
		log.Printf("User %s tries to authorize from %s...", username, c.ClientIP())
		cErr = authenticator.Authorize(c, username, password)
		if cErr != nil {
			log.Printf("User %s failed to authorize from %s because of %s", username, c.ClientIP(), cErr.Error())
			session.AddFlash(fmt.Sprintf("Authorization error  %s", cErr))
			c.Redirect(http.StatusFound, "/")
			return
		} else {
			log.Printf("User %s authorized from %s!", username, c.ClientIP())
			session.AddFlash(fmt.Sprintf("Welcome, %s!", username))
		}
		user, cErr := authenticator.Extract(c)
		if cErr != nil {
			log.Printf("%s : while extracting user", cErr)
		} else {
			log.Printf("user %s is extracted", user.DN)
		}
		c.Redirect(http.StatusFound, "/")
	})

	// page to list groups
	r.GET("/groups", func(c *gin.Context) {
		session := sessions.Default(c)
		defer session.Save()
		flashes := session.Flashes()
		user, cErr := authenticator.Extract(c)
		if cErr != nil {
			session.AddFlash(fmt.Sprintf("Authorization error  %s", cErr))
			c.Redirect(http.StatusFound, "/")
			return
		}
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
