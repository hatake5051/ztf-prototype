package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hatake5051/ztf-prototype/actors/rp"
)

func main() {
	raw, err := ioutil.ReadFile("./conf.json")
	if err != nil {
		panic(err)
	}
	var conf rp.Conf
	if err := json.Unmarshal(raw, &conf); err != nil {
		panic(err)
	}
	r := rp.New(conf.New)
	http.Handle("/", r)
	log.Println("server starting...")
	if err := http.ListenAndServe(":80", r); err != nil {
		log.Fatal(err)
	}
}
