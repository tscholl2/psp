package psp

import (
	"fmt"
	"testing"
)

func TestT(t *testing.T) {
	// TODO write test functions with static primes/date
	var s string
	k, err := NewRsaKey(1024 * 2)
	if err != nil {
		panic(err)
	}
	e, err := NewEntity("name", "comment", "email", k)
	if err != nil {
		panic(err)
	}
	s, err = ArmorUpPublic(e)
	if err != nil {
		panic(err)
	}
	fmt.Println(s)
	s, err = ArmorUpPrivate(e)
	if err != nil {
		panic(err)
	}
	fmt.Println(s)
	s, err = ArmorUpCertificateRequest(e)
	if err != nil {
		panic(err)
	}
	fmt.Println(s)
}
