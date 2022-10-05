package main

import (
	"fmt"
	"log"
	"time"
	"net/http"
	"sort"
)

func handler(w http.ResponseWriter, r *http.Request) {
	var headers []string
	w.Header().Set("Content-Type", "text/plain")
	fmt.Printf("request at %v\n", time.Now())
	for k, v := range r.Header {
		headers = append(headers, fmt.Sprintf("%v: %v\n", k, v))
	}
	sort.Strings(headers)
	for _, v := range headers {
		w.Write([]byte(v))
		fmt.Printf(v)
	}
}

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
