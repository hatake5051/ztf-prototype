package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hatake5051/ztf-prototype/actors/cap"
)

func main() {
	raw, err := ioutil.ReadFile("./conf.json")
	if err != nil {
		panic(err)
	}
	var conf cap.Conf
	if err := json.Unmarshal(raw, &conf); err != nil {
		panic(err)
	}
	r := conf.New()
	http.Handle("/", r)
	if err := http.ListenAndServe(":9090", r); err != nil {
		log.Fatal(err)
	}
}
