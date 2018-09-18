package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userName, password, _ := r.BasicAuth()

	if userName != "admin" || password != "admin" {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Hello, world!")
}

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
