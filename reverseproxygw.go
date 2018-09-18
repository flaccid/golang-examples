package main

import (
	//"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	userName, password, _ := r.BasicAuth()

	if userName != "admin" || password != "admin" {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	origin, _ := url.Parse("https://icanhazip.com/")

	director := func(r *http.Request) {
		r.URL.Scheme = origin.Scheme
		r.URL.Host = origin.Host
	}

	proxy := &httputil.ReverseProxy{Director: director}

	proxy.ServeHTTP(w, r)
}

func main() {
	http.HandleFunc("/", proxyHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
