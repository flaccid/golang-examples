package main

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	gcontext "github.com/gorilla/context"
	log "github.com/sirupsen/logrus"
	plus "google.golang.org/api/plus/v1"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type OAuthApp struct {
	Config oauth2.Config
	State  string
}

type Profile struct {
	ID, DisplayName, ImageURL string
}

const (
	// set the default sessions keys
	defaultSessionID        = "default"
	googleProfileSessionKey = "google_profile"
	oauthTokenSessionKey    = "oauth_token"

	// This key is used in the OAuth flow session to store the URL to redirect the
	// user to after the OAuth flow is complete.
	oauthFlowRedirectKey = "redirect"
)

var (
	letterRunes   = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	encryptionKey = []byte(securecookie.GenerateRandomKey(64))
	SessionStore  = sessions.NewCookieStore(encryptionKey)
	app           = OAuthApp{
		Config: oauth2.Config{
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
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

// fetchProfile retrieves the Google+ profile of the user associated with the
// provided OAuth token.
func fetchProfile(ctx context.Context, tok *oauth2.Token) (*plus.Person, error) {
	client := oauth2.NewClient(ctx, app.Config.TokenSource(ctx, tok))
	plusService, err := plus.New(client)
	if err != nil {
		return nil, err
	}
	log.Debug("profile", plusService.People.Get("me"))
	return plusService.People.Get("me").Do()
}

// stripProfile returns a subset of a plus.Person.
func stripProfile(p *plus.Person) *Profile {
	return &Profile{
		ID:          p.Id,
		DisplayName: p.DisplayName,
		ImageURL:    p.Image.Url,
	}
}

// profileFromSession retreives the Google+ profile from the default session.
// Returns nil if the profile cannot be retreived (e.g. user is logged out).
func profileFromSession(r *http.Request) *Profile {
	session, err := SessionStore.Get(r, defaultSessionID)
	if err != nil {
		log.Error(err, "could not get default session: %v", err)
	}
	tok, ok := session.Values[oauthTokenSessionKey].(*oauth2.Token)
	if !ok || !tok.Valid() {
		return nil
	}
	profile, ok := session.Values[googleProfileSessionKey].(*Profile)
	if !ok {
		return nil
	}
	return profile
}

func publicHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "", "<html><body><p>This is a public page.</p><p><a href=\"/login\">login</a> | <a href=\"/logout\">logout</a></p></body></html>")
}

// logoutHandler clears the default session.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := SessionStore.New(r, defaultSessionID)
	if err != nil {
		log.Error(err, "could not get default session: %v", err)
	}
	session.Options.MaxAge = -1 // Clear session.
	if err := session.Save(r, w); err != nil {
		log.Error(err, "could not save session: %v", err)
	}
	redirectURL := r.FormValue("redirect")
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func secretHandler(w http.ResponseWriter, r *http.Request) {
	session, err := SessionStore.Get(r, defaultSessionID)
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

func profileHandler(w http.ResponseWriter, r *http.Request) {
	session, err := SessionStore.Get(r, defaultSessionID)
	if err != nil {
		log.Error(err, "could not get default session: %v", err)
	}

	// TODO: add logic to check actual oauth session
	// check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	profile := profileFromSession(r)
	body := "<html><body><h1>" + profile.DisplayName + "</h1><h2>" + profile.ID + "</h2><p><img src=\"" + profile.ImageURL + "\"/ >" + "</p></body></html>"

	// render the profile html page
	fmt.Fprintln(w, body)
}

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := uuid.Must(uuid.NewV4()).String()

	oauthFlowSession, err := SessionStore.New(r, sessionID)
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
		log.Error(err, "could not save session: %v", err)
	}

	// Use the session ID for the "state" parameter.
	// This protects against CSRF (cross-site request forgery).
	// See https://godoc.org/golang.org/x/oauth2#Config.AuthCodeURL for more detail.
	url := app.Config.AuthCodeURL(sessionID, oauth2.ApprovalForce,
		oauth2.AccessTypeOnline)
	log.Debug("url", url)
	http.Redirect(w, r, url, http.StatusFound)
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	oauthFlowSession, err := SessionStore.Get(r, r.FormValue("state"))
	if err != nil {
		log.Error(err, "invalid state parameter. try logging in again.")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	}
	log.Debug(oauthFlowSession)

	redirectURL, ok := oauthFlowSession.Values[oauthFlowRedirectKey].(string)
	log.Debug(redirectURL)
	// Validate this callback request came from the app.
	if !ok {
		log.Error("invalid state parameter. try logging in again.")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	}

	code := r.FormValue("code")
	tok, err := app.Config.Exchange(context.Background(), code)
	if err != nil {
		log.Error(err, "could not get auth token: %v", err)
	}

	session, err := SessionStore.New(r, defaultSessionID)
	if err != nil {
		log.Error(err, "could not get default session: %v", err)
	}

	ctx := context.Background()

	profile, err := fetchProfile(ctx, tok)
	if err != nil {
		log.Error(err, "could not fetch Google profile: %v", err)
	}
	log.Debug(profile)

	session.Values[oauthTokenSessionKey] = tok
	// Strip the profile to only the fields we need. Otherwise the struct is too big.
	session.Values[googleProfileSessionKey] = stripProfile(profile)
	// set user as authenticated
	session.Values["authenticated"] = true

	if err := session.Save(r, w); err != nil {
		log.Error(err, "could not save session: %v", err)
	}
	log.Debug("session values", session.Values)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func Serve(clientId string, clientSecret string, redirectUrl string) {
	app.Config.ClientID = clientId
	app.Config.ClientSecret = clientSecret
	app.Config.RedirectURL = redirectUrl
	app.State = RandStringRunes(255)
	SessionStore.Options = &sessions.Options{
		HttpOnly: true,
	}

	log.Debug("app", app)
	log.Debug("session store", SessionStore)

	http.HandleFunc("/oauth2callback", googleCallbackHandler)
	http.HandleFunc("/login", googleLoginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/secret", secretHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/", publicHandler)

	http.ListenAndServe(":8080", gcontext.ClearHandler(http.DefaultServeMux))
}

func main() {
	rand.Seed(time.Now().UnixNano())
	log.SetLevel(log.DebugLevel)

	// Gob encoding for gorilla/sessions
	gob.Register(&oauth2.Token{})
	gob.Register(&Profile{})

	Serve(os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET"), os.Getenv("REDIRECT_URL"))
}
