package ldap4gin

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var authenticator *Authenticator
var app *gin.Engine

const sessionCookieName = "mysession"

var testUsername string
var testPassword string

func TestEnvironment(t *testing.T) {
	testUsername = os.Getenv("TEST_LDAP_USERNAME")
	assert.NotEmpty(t, testUsername, "test username is not set")
	testPassword = os.Getenv("TEST_LDAP_PASSWORD")
	assert.NotEmpty(t, testPassword, "test password is not set")
}

func TestNewFail(t *testing.T) {
	_, err := New(&Options{
		Debug:            true,
		ConnectionString: "ldap://there.is.no.ldap.example.org:389",
		UserBaseTpl:      "uid=%s,ou=people,dc=vodolaz095,dc=life",
		ExtraFields:      []string{"l"}, // get location too
	})
	if err != nil {
		if strings.Contains(err.Error(), "lookup there.is.no.ldap.example.org: no such host") {
			return
		}
		t.Error(err)
	}
	t.Errorf("we connected to non existent ldap?")
}

func TestNewSuccess(t *testing.T) {
	a, err := New(&Options{
		Debug:            true,
		ConnectionString: "ldap://127.0.0.1:389",
		UserBaseTpl:      "uid=%s,ou=people,dc=vodolaz095,dc=life",
		ExtraFields:      []string{"l"}, // get location too
		TLS: &tls.Config{
			InsecureSkipVerify: true, // NEVER DO IT
		},
	})
	if err != nil {
		t.Error(err)
	}
	t.Logf("Authenticator initialized")
	authenticator = a
}

func TestAuthenticatorClient(t *testing.T) {
	result, err := authenticator.LDAPConn.WhoAmI(nil)
	if err != nil {
		t.Error(err)
	}
	t.Logf("AuthzID: %s", result.AuthzID)
}

func TestCreateApp(t *testing.T) {
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions(sessionCookieName, store))
	r.GET("/", func(c *gin.Context) {
		user, err := authenticator.Extract(c)
		if err != nil {
			if err.Error() == "unauthorized" {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			panic(err) // something wrong, like LDAP server stopped
		}
		c.String(http.StatusOK, "User: %s", user.DN)
	})
	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		fmt.Printf("Authorizing as %s %s...\n", username, password)
		err := authenticator.Authorize(c, username, password)
		if err != nil {
			fmt.Printf("Error >%s<\n", err.Error())
			if err.Error() == "invalid credentials" {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			if err.Error() == "malformed username" {
				c.AbortWithStatus(http.StatusTeapot)
				return
			}
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.AbortWithStatus(http.StatusAccepted)
	})
	r.GET("/logout", func(c *gin.Context) {
		authenticator.Logout(c)
		c.AbortWithStatus(http.StatusOK)
	})
	app = r
}

func TestUnauthorized(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"http://russian.rt.com/",
		nil,
	) // GIN engine should ignore HOSTNAME in header, so its ok if i provide it here
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "wrong status code")
}

func TestAuthenticator_Authorize_fail(t *testing.T) {
	data := url.Values{}
	data.Add("username", "thisIsUserNeverExistedInLDAP")
	data.Add("password", "someRandomPasswordNobodyUses")
	t.Logf("Body encoded - %s", data.Encode())
	req := httptest.NewRequest(
		"POST",
		"http://russian.rt.com/login",
		strings.NewReader(data.Encode()),
	) // GIN engine should ignore HOSTNAME in header, so its ok if i provide it here
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "wrong status code")
}

func TestAuthenticator_Authorize_malformed(t *testing.T) {
	data := url.Values{}
	data.Add("username", "thisIsMalformedUsername)}")
	data.Add("password", "someRandomPasswordNobodyUses")
	t.Logf("Body encoded - %s", data.Encode())
	req := httptest.NewRequest(
		"POST",
		"http://russian.rt.com/login",
		strings.NewReader(data.Encode()),
	) // GIN engine should ignore HOSTNAME in header, so its ok if i provide it here
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusTeapot, resp.StatusCode, "wrong status code")
}

var testSessionCookie *http.Cookie

func TestAuthenticator_Authorize_pass(t *testing.T) {
	data := url.Values{}
	data.Add("username", testUsername)
	data.Add("password", testPassword)
	t.Logf("Body encoded - %s", data.Encode())
	req := httptest.NewRequest(
		"POST",
		"http://russian.rt.com/login",
		strings.NewReader(data.Encode()),
	) // GIN engine should ignore HOSTNAME in header, so its ok if i provide it here
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode, "wrong status code")
	var sessionCookieFound bool
	for _, cookie := range resp.Cookies() {
		t.Logf("Cookie %s with value %s found!", cookie.Name, cookie.Value)
		if cookie.Name == sessionCookieName {
			sessionCookieFound = true
			testSessionCookie = cookie
		}
	}
	assert.True(t, sessionCookieFound, "session cookie %s not found")
	t.Logf("Session cookie: %s", testSessionCookie)
}

func TestAuthenticator_Extract_pass(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"http://russian.rt.com/",
		nil,
	) // GIN engine should ignore HOSTNAME in header, so its ok if i provide it here
	req.AddCookie(testSessionCookie)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "wrong status code")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	t.Logf("Body - %s", string(body))
	assert.Equal(t,
		fmt.Sprintf("User: uid=%s,ou=people,dc=vodolaz095,dc=life", os.Getenv("TEST_LDAP_USERNAME")),
		string(body),
		"wrong body",
	)
}

func TestAuthenticator_Logout(t *testing.T) {
	oldVal := testSessionCookie.Value
	req := httptest.NewRequest(
		"GET",
		"http://russian.rt.com/logout",
		nil,
	) // GIN engine should ignore HOSTNAME in header, so its ok if i provide it here
	req.AddCookie(testSessionCookie)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "wrong status code")
	var sessionCookieFound bool
	for _, cookie := range resp.Cookies() {
		t.Logf("Cookie %s with value %s found!", cookie.Name, cookie.Value)
		if cookie.Name == sessionCookieName {
			sessionCookieFound = true
			testSessionCookie = cookie
		}
	}
	assert.True(t, sessionCookieFound, "session cookie %s not found")
	t.Logf("Session cookie: %s", testSessionCookie)
	assert.NotEqual(t, oldVal, testSessionCookie.Value, "cookie not upgraded")
}

func TestAuthenticator_Extract_fail(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"http://russian.rt.com/",
		nil,
	) // GIN engine should ignore HOSTNAME in header, so its ok if i provide it here
	req.AddCookie(testSessionCookie)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	resp := w.Result()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "wrong status code")
}
