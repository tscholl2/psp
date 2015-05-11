package main

import (
	"encoding/base64"
	"fmt"

	"github.com/tscholl2/psp/psp"
)

func main() {
	k, _ := psp.NewRsaKey()
	//fmt.Println(base64.StdEncoding.EncodeToString(k.PublicKey.N.Bytes()))
	//fmt.Println(base64.StdEncoding.EncodeToString(k.Primes[0].Bytes()))
	//fmt.Println(base64.StdEncoding.EncodeToString(k.Primes[1].Bytes()))
	e, err := psp.NewEntity("name", "comment", "em@il", k)
	if err != nil {
		fmt.Errorf("errorrrrrr: %s", err.Error())
	}
	fmt.Println(psp.ArmorUp(e))
	fmt.Println("")

	s := `xsBNBFVQJQ0BCADRmS3881y2o2gFsyGhr2Fggao9ESVcrlWuyQLqCI91uAT2lKX+
2GKz+y2uKeD+Kz/rj9yFqtpy16uz+WieD92ie3/Ki7+x57+2Fq3+mV5qx7+x57/E
mdxtmhbpcCw1QFvON/92UtPUgxNvjLesV5SSoaRKwMVlcC7QYNLZay+unCggA9Sc
AUBjBbli0cfMO84XxA3xXbwZcDYHPbi2FEBM1oEE3XPGM/J/wvobgcuKaTNaKjkB
xEtUBLX6gB841auYwFOlKDiDhe7OLPRLyVXdEoAmE4/kWK1whIwnlh8apvgXU5L3
IwQiFdNgYh5ogm+1sECf6+vJZ0bAMPMBRugdABEBAAHNFm5hbWUgKGNvbW1lbnQp
IDxlbUBpbD7CwGIEEwEIABYFAlVQJQ0JEE9ewB5bqJl0AhsDAhkBAAANXwgAaaPW
Ie1LFtYRxoKpZwA4Oy3Hoo9ptf2tUPZQIoyymFaVbIzjnUbzXxAyaARMiSlbsbuH
BdhUQwfOAqpZfAMOHFkAPusmNV//l3XUZFjnnACN74c41q6wHeH3a7EhWaIYo7Cm
L7DjHCCIMB+ZSIhgPQ2O5QH6y0G2TjZhvz8xnPUmehV96WnGTDxuN3jjlMFyrDXs
bBsLP51kriDTY5Ne+bj5Zw1fw5ymwRDV6dsW0R9qMciqW2ouqme+N3pLPqXCnzpT
XIjL6qyidvZ1LvhFvZ9gqTNXLbUJs87fjRORfB6FDp2r2BDUacbsAesr6kLz5W9w
P1UoBAkDTZhEwLYsJA==
=zqX3`

	b, err := base64.StdEncoding.DecodeString(s)
	fmt.Printf("BYTES=\n%X\n", b)

	//var buffer bytes.Buffer

	//e.SerializePrivate(&buffer, nil)
	//data := base64.StdEncoding.EncodeToString([]byte(buffer.String()))
	//fmt.Printf("%q\n", data)

	//e.Serialize(&buffer)
	//data2 := base64.StdEncoding.EncodeToString([]byte(buffer.String()))
	//fmt.Printf("%q\n", data2)

	//e.PrivateKey.Serialize(&buffer)
	//data3 := base64.StdEncoding.EncodeToString([]byte(buffer.String()))
	//fmt.Printf("%q\n", data3)

	//e.PrimaryKey.Serialize(&buffer)
	//data4 := base64.StdEncoding.EncodeToString([]byte(buffer.String()))
	//fmt.Printf("%q\n", data4)

	//fmt.Printf("kN=\n%X\n", k.PublicKey.N)

	//fmt.Printf("eN=\n%X\n", e.PrimaryKey.PublicKey.(*rsa.PublicKey).N)

	//fmt.Printf("N=\n%X\n", k.PublicKey.N)
	//fmt.Println(base64.StdEncoding.EncodeToString(k.PublicKey.N.Bytes()))

}
