package rp2

import (
	"github.com/hatake5051/ztf-prototype/ac/pdp"
	"github.com/hatake5051/ztf-prototype/ac/pip"
)

type Conf struct {
	PIP pip.Conf `json:"pip"`
	PDP pdp.Conf `json:"pdp"`
}
