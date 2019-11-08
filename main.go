package main

import (
	"log"
	"net/http"
	"soturon/actors"
)

func main() {
	go func() {
		if err := http.ListenAndServe(":9000", actors.NewPEF()); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		if err := http.ListenAndServe(":9002", actors.NewIDP()); err != nil {
			log.Fatal(err)
		}
	}()

	if err := http.ListenAndServe(":9001", actors.NewCAP()); err != nil {
		log.Fatal(err)
	}

}
