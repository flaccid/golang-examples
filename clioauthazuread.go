// adapted from https://gist.github.com/marians/3b55318106df0e4e648158f1ffb43d38
// - use microsoft endpoints
// - add settings from env
// - add forward proxy support
// - add tenant support for endpoints

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
  "os"
	"time"

	"github.com/fatih/color"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

var (
	conf *oauth2.Config
	ctx  context.Context
)

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	queryParts, _ := url.ParseQuery(r.URL.RawQuery)

	// Use the authorization code that is pushed to the redirect
	// URL.
	code := queryParts["code"][0]
	log.Printf("code: %s\n", code)

	// Exchange will do the handshake to retrieve the initial access token.
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %s", tok)
	// The HTTP Client returned by conf.Client will refresh the token as necessary.
	client := conf.Client(ctx, tok)

	// should be a private page only accessible by the token
	resp, err := client.Get(os.Getenv("REFRESH_URL"))
  log.Printf("refresh page response: %s", resp)
	// note: a non-200 or fail is possible here without returning error
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println(color.CyanString("Authentication successful"))
	}
	defer resp.Body.Close()

	// show succes page
	msg := "<p><strong>Success!</strong></p>"
	msg = msg + "<p>You are authenticated and can now return to the CLI.</p>"
	fmt.Fprintf(w, msg)
}

func main() {
	ctx = context.Background()
	conf = &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"openid", "profile"},
    Endpoint:     microsoft.AzureADEndpoint(""),
		// my own callback URL
		RedirectURL: "http://localhost:8080/oauth2callback",
	}

  if len(os.Getenv("TENANT_ID")) > 1 {
		conf.Endpoint = microsoft.AzureADEndpoint(os.Getenv("TENANT_ID"))
	}

	// add transport for self-signed certificate to context
	tr := &http.Transport{
    Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	sslcli := &http.Client{Transport: tr}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, sslcli)

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)

	log.Println(color.CyanString("You will now be taken to your browser for authentication"))
	time.Sleep(1 * time.Second)
	open.Run(url)
	time.Sleep(1 * time.Second)
	log.Printf("Authentication URL: %s\n", url)

	http.HandleFunc("/oauth2callback", callbackHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))

}
