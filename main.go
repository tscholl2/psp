package main

import (
	"fmt"

	"github.com/tscholl2/psp/psp"
)

func main() {
	k, _ := psp.NewRsaKey()
	//fmt.Println(base64.StdEncoding.EncodeToString(k.PublicKey.N.Bytes()))
	//fmt.Println(base64.StdEncoding.EncodeToString(k.Primes[0].Bytes()))
	//fmt.Println(base64.StdEncoding.EncodeToString(k.Primes[1].Bytes()))
	e := psp.NewEntity("name", "comment", "em@il", k)
	fmt.Println(psp.ArmorUp(e))
	fmt.Println("")
}
