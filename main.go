package main

import (
	"fmt"

	"github.com/tscholl2/psp/psp"
)

func main() {
	var s string
	var err error
	k, _ := psp.NewRsaKey(2048, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", 1)

	e, err := psp.NewEntity("name", "comment", "em@il", k)
	if err != nil {
		fmt.Errorf("Error: %s", err.Error())
	}

	//s, err = psp.ExportPublicPEM(k.Public().(*rsa.PublicKey))
	//s, err = psp.ExportPrivatePEM(k)
	//s, err = psp.ExportPrivatePGP(e)
	s, err = psp.ExportPublicPGP(e)
	if err != nil {
		fmt.Errorf("Error: %s", err.Error())
	}
	fmt.Println(s)
}
