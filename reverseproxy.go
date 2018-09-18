package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	url, _ := url.Parse("https://icanhazip.com/")
	http.Handle("/", httputil.NewSingleHostReverseProxy(url))

	http.ListenAndServe(":8080", nil)
}
