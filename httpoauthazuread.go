package main

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	gcontext "github.com/gorilla/context"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// environment requirements
// CLIENT_ID - oauth client id
// CLIENT_SECRET - oauth client secret
// REDIRECT_URL - redirect url (http://localhost:8080/oauth2callback)
// TENANT_ID - Azure tenant id

type OAuthApp struct {
	Config   oauth2.Config
	State    string
	TenantId string
}

const (
	// set the default sessions keys
	defaultSessionID     = "default"
	oauthTokenSessionKey = "oauth_token"

	// This key is used in the OAuth flow session to store the URL to redirect the
	// user to after the OAuth flow is complete.
	oauthFlowRedirectKey = "redirect"
)

var (
	letterRunes   = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	encryptionKey = []byte(securecookie.GenerateRandomKey(64))
	userInfo      []byte
	Store         = sessions.NewFilesystemStore(os.TempDir(), encryptionKey)

	App = OAuthApp{
		Config: oauth2.Config{
			Scopes: []string{
				"openid",
				"profile",
				"email",
				"User.Read",
			},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
				TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			},
		},
	}
)

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// validateRedirectURL checks that the URL provided is valid.
// If the URL is missing, redirect the user to the application's root.
// The URL must not be absolute (i.e., the URL must refer to a path within this
// application).
func validateRedirectURL(path string) (string, error) {
	if path == "" {
		return "/", nil
	}

	// Ensure redirect URL is valid and not pointing to a different server.
	parsedURL, err := url.Parse(path)
	if err != nil {
		return "/", err
	}
	if parsedURL.IsAbs() {
		return "/", errors.New("URL must not be absolute")
	}
	return path, nil
}

func getUserInfo(app OAuthApp, accessToken string) ([]byte, error) {
	// https://stackoverflow.com/questions/49449654/how-do-i-get-the-logged-in-users-profile-for-azure-ad-oauth-logins
	userInfoEndpoint := "https://graph.microsoft.com/v1.0/me"
	// this oauth2 standard endpoint does not seem to work (returns http 400)
	// userInfoEndpoint := "https://login.microsoftonline.com/" + App.TenantId + "/openid/userinfo"

	log.Debugf("fetch user info using ", userInfoEndpoint)
	log.Debugf("access token: ", accessToken)

	client := &http.Client{}
	request, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		log.Fatalln(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	log.Debugf("userinfo response: ", response)

	return contents, nil
}

func publicHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "", "<html><body><p>This is a public page.</p><p><a href=\"/login\">login</a> | <a href=\"/logout\">logout</a></p></body></html>")
}

// logoutHandler clears the default session.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := Store.New(r, defaultSessionID)
	if err != nil {
		log.Errorf("could not get default session: ", err)
	}
	session.Options.MaxAge = -1 // Clear session.
	if err := session.Save(r, w); err != nil {
		log.Errorf("could not save session: ", err)
	}
	redirectURL := r.FormValue("redirect")
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func secretHandler(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, defaultSessionID)
	if err != nil {
		log.Error(err, "could not get default session: %v", err)
	}

	log.Debug("session info", session)

	// check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// print secret message
	fmt.Fprintln(w, "The cake is a lie!")
}

func azureADLoginHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := uuid.Must(uuid.NewV4()).String()

	oauthFlowSession, err := Store.New(r, sessionID)
	if err != nil {
		log.Error(err, "could not create oauth session: %v", err)
	}
	oauthFlowSession.Options.MaxAge = 10 * 60 // 10 minutes
	log.Debug("oauth flow session", oauthFlowSession)

	redirectURL, err := validateRedirectURL(r.FormValue("redirect"))
	if err != nil {
		log.Error(err, "invalid redirect URL: %v", err)
	}
	oauthFlowSession.Values[oauthFlowRedirectKey] = redirectURL

	if err := oauthFlowSession.Save(r, w); err != nil {
		log.Error(err, "could not save oauth flow session: %v", err)
	}

	// Use the session ID for the "state" parameter.
	// This protects against CSRF (cross-site request forgery).
	// See https://godoc.org/golang.org/x/oauth2#Config.AuthCodeURL for more detail.
	url := App.Config.AuthCodeURL(sessionID, oauth2.ApprovalForce,
		oauth2.AccessTypeOnline)
	log.Debug("url", url)
	http.Redirect(w, r, url, http.StatusFound)
}

func azureADCallbackHandler(w http.ResponseWriter, r *http.Request) {
	oauthFlowSession, err := Store.Get(r, r.FormValue("state"))
	if err != nil {
		log.Error(err, "invalid state parameter. try logging in again.")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	}
	log.Debug(oauthFlowSession)

	redirectURL, ok := oauthFlowSession.Values[oauthFlowRedirectKey].(string)
	log.Debug(redirectURL)
	// Validate this callback request came from the App.
	if !ok {
		log.Error("invalid state parameter. try logging in again.")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	}

	code := r.FormValue("code")
	tok, err := App.Config.Exchange(context.Background(), code)
	if err != nil {
		log.Error(err, "could not get auth token: %v", err)
	}

	session, err := Store.New(r, defaultSessionID)
	if err != nil {
		log.Error(err, "could not get default session: %v", err)
	}

	session.Values[oauthTokenSessionKey] = tok

	// set user as authenticated
	session.Values["authenticated"] = true

	if err := session.Save(r, w); err != nil {
		log.Error(err, "could not save session: %v", err)
	}
	log.Debug("session values", session.Values)
	log.Debug(session.Values["oauth_token"])

	// get openid user info
	userInfo, err = getUserInfo(App, tok.AccessToken)
	if err != nil {
		log.Error(err)
	} else {
		log.Debugf("user info: ", string(userInfo))
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func Serve() {
	http.HandleFunc("/oauth2callback", azureADCallbackHandler)
	http.HandleFunc("/login", azureADLoginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/secret", secretHandler)
	http.HandleFunc("/", publicHandler)
	http.ListenAndServe(":8080", gcontext.ClearHandler(http.DefaultServeMux))
}

func init() {
	rand.Seed(time.Now().UnixNano())

	// set the maxLength of the cookies stored on the disk to a larger number to prevent issues with:
	// securecookie: the value is too long
	// when using OpenID Connect , since this can contain a large amount of extra information in the id_token

	// Note, when using the FilesystemStore only the session.ID is written to a browser cookie, so this is explicit for the storage on disk
	Store.MaxLength(math.MaxInt64)
}

func main() {
	log.SetLevel(log.DebugLevel)

	// gob encoding for gorilla/sessions
	gob.Register(&oauth2.Token{})

	// configure the application properties
	App.Config.ClientID = os.Getenv("CLIENT_ID")
	App.Config.ClientSecret = os.Getenv("CLIENT_SECRET")
	App.Config.RedirectURL = os.Getenv("REDIRECT_URL")
	App.TenantId = os.Getenv("TENANT_ID")
	App.State = RandStringRunes(255)
	// sessionStore.Options = &sessions.Options{
	// 	HttpOnly: true,
	// }
	if len(os.Getenv("TENANT_ID")) > 1 {
		App.Config.Endpoint = microsoft.AzureADEndpoint(App.TenantId)
	}
	log.Debug("App: ", App)

	Serve()
}
