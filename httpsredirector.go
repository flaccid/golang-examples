package main

import (
	"log"
	"net/http"
)

var code int = http.StatusTemporaryRedirect

func handler(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
  if r.Method == http.MethodGet {
    code = http.StatusMovedPermanently
  }
  http.Redirect(w, r, target, code)
  log.Printf("%v %v", code, target)
}

func main() {
  http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
