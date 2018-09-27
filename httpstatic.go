package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	port := flag.String("p", "8080", "port to listen on")
	directory := flag.String("d", ".", "directory of static files to host")
	flag.Parse()

	http.Handle("/", http.FileServer(http.Dir(*directory)))

	log.Printf("serving %s on %s\n", *directory, *port)
	log.Fatal(http.ListenAndServe(":"+*port, nil))
}
