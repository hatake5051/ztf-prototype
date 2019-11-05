package main

import (
	"log"
	"net/http"
	"soturon/infra"
)

func main() {
	go func() {
		if err := http.ListenAndServe(":9000", infra.NewPEF()); err != nil {
			log.Fatal(err)
		}
	}()

	if err := http.ListenAndServe(":9001", infra.NewCAP()); err != nil {
		log.Fatal(err)
	}

}
