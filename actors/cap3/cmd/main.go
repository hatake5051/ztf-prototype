package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hatake5051/ztf-prototype/actors/cap3"
)

func main() {
	raw, err := ioutil.ReadFile("./conf.json")
	if err != nil {
		panic(err)
	}
	var conf cap3.Conf
	if err := json.Unmarshal(raw, &conf); err != nil {
		panic(err)
	}
	r := conf.New()
	http.Handle("/", r)
	if err := http.ListenAndServe(":80", r); err != nil {
		log.Fatal(err)
	}
}
