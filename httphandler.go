package main

import (
	"fmt"
	"log"
	"net/http"
)

type Meta struct {
	msg string
}

func main() {
	data := &Meta{msg: "Hello, world!"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "", string(data.msg))
	})

	err := http.ListenAndServe(":8080", handler)
	log.Fatal(err)
}
