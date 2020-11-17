package main

import (
	"log"
	"net/http"

	"github.com/hatake5051/ztf-prototype/actors/cap"
)

func main() {
	c := cap.Conf{
		Issuer:       "http://idp.ztf-proto.k3.ipv6.mobi/auth/realms/ztf-proto",
		OIDCRPID:     "cap1",
		OIDCRPSecret: "66be9519-4ec8-42dc-ab07-3e7caad187fc",
		Host:         "http://localhost:9090",
	}
	r := c.New()
	http.Handle("/", r)
	if err := http.ListenAndServe(":9090", r); err != nil {
		log.Fatal(err)
	}
}
