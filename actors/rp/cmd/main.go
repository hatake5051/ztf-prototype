package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hatake5051/ztf-prototype/ac"
	"github.com/hatake5051/ztf-prototype/ac/config"
	"github.com/hatake5051/ztf-prototype/ac/controller"
	"github.com/hatake5051/ztf-prototype/actors/rp"
)

func main() {
	raw, err := ioutil.ReadFile("./conf.json")
	if err != nil {
		panic(err)
	}
	var conf config.Conf
	if err := json.Unmarshal(raw, &conf); err != nil {
		panic(err)
	}
	idp := "http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/ztf-proto-idp2"
	repo := ac.NewRepo()
	pip, err := conf.PIP.To().New(repo)
	if err != nil {
		panic(err)
	}
	pdp, err := conf.PDP.To().New()
	if err != nil {
		panic(err)
	}
	r := rp.New(idp, controller.New(pip, pdp))
	http.Handle("/", r)
	log.Println("server starting...")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
