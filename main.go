package main

import (
	"fmt"
	"math/big"

	"github.com/tscholl2/psp/psp"
)

func main() {
	k, _ := psp.NewRsaKey(2048)
	//fmt.Println(base64.StdEncoding.EncodeToString(k.PublicKey.N.Bytes()))
	//fmt.Println(base64.StdEncoding.EncodeToString(k.Primes[0].Bytes()))
	//fmt.Println(base64.StdEncoding.EncodeToString(k.Primes[1].Bytes()))
	//fmt.Printf("p=\n%x\n", k.Primes[0])
	//fmt.Printf("q=\n%x\n", k.Primes[1])
	fmt.Printf("n=\n%x\n", new(big.Int).Mul(k.Primes[0], k.Primes[1]))
	e, err := psp.NewEntity("name", "comment", "em@il", k)
	if err != nil {
		fmt.Errorf("Error: %s", err.Error())
	}
	s, _ := psp.ArmorUpCertificateRequest(e)
	/// use this to inspect the modulous
	// openssl req -in csr.txt -noout -text

	// use this to inspect modulous of certificate
	// openssl x509 -in cert.txt -noout -text

	fmt.Println(s)

	s, _ = psp.ArmorUpPrivatePem(e)

	fmt.Println(s)
}
