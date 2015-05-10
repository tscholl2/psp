package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

const (
	// PublicKeyType is the armor type for a PGP public key.
	PublicKeyType = "SASSY PGP PUBLIC KEY"
	// PrivateKeyType is the armor type for a PGP private key.
	PrivateKeyType = "SASSY PGP PRIVATE KEY"
	// SignatureType is the armor type for a PGP signature.
	SignatureType = "PGP SIGNATURE"
)

// SassyPrimes returns p,q
// so that base64 of N=p*q
// contains a sassy string
func SassyPrimes() (p *big.Int, q *big.Int, err error) {
	//important to be 64 characters long
	sassStr := "//When/cryptography/is/outlawed/bayl/bhgynjf/jvyy/unir/cevinpl//"
	sass, _ := base64.StdEncoding.DecodeString(sassStr)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Errorf("Error generating primes: %s", err)
	}
	p = key.Primes[0]
	q = key.Primes[1]
	N := new(big.Int).Mul(p, q)
	fmt.Printf("N = %X\np = %X\nq = %X\n", N, p, q)

	s := base64.StdEncoding.EncodeToString(N.Bytes())
	fmt.Println("OLD N")
	fmt.Println(s)

	b := N.Bytes()
	offset := 36
	for i := 0; i < len(sass); i++ {
		b[i+offset] = sass[i]
	}
	N.SetBytes(b)

	s = base64.StdEncoding.EncodeToString(N.Bytes())
	fmt.Println("NEW N")
	fmt.Println(s)

	qtmp := new(big.Int).Div(N, p)
	q, err = rand.Prime(rand.Reader, qtmp.BitLen())
	N = N.Mul(p, q)
	s = base64.StdEncoding.EncodeToString(N.Bytes())
	fmt.Println("FINAL N")
	fmt.Println(s)

	return
}

func main() {
	/*
		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			fmt.Errorf("Error generating private key: %s", err)
		}
	*/

	p, _ := new(big.Int).SetString("CBCD788F231A013FC231766BC683567278D6CBDC8CDE38DAF33D33AD2A9B3EFDEC91895CF65E21A919E635EB460E6F346CAC459DADE090F1F0AD41DCE367FBDD", 16)
	q, _ := new(big.Int).SetString("E3CCE2A15B9D668936EAD7164EEF5DD0DBA748F4344FD7D3AF2727BA61895E5208ABA9E0B84D9265909CF3105A96AB4E4EC01C6AAC18F41E152A8571242E6441", 16)
	D, _ := new(big.Int).SetString("B4A389C2F11CFFE297BAC8F286B7B02FEF43D6EDA47E2A4640B5882A810B8B5AEC3D1E7B160843B2A3346C873674446218C01944C2B1C78BB08B392D35D75F2DFAEF9798716C0A2474D34D00EED87DB5A608EE33F4E0AB9E636F046B2FB11A751245DC4D0D41BFC785F035FE673E9DD91C5D33FF017E12CA2C3576CC3B2F1901", 16)
	E := 65537
	privateKey := rsa.PrivateKey{
		D:      D,
		Primes: []*big.Int{p, q},
		PublicKey: rsa.PublicKey{
			N: new(big.Int).Mul(p, q),
			E: E}}
	privateKey.Precompute()

	//fmt.Printf("p = %X\n", p)
	//fmt.Printf("q = %X\n", q)
	//fmt.Printf("D = %X\n", privateKey.D)
	//fmt.Printf("E = %d\n", privateKey.PublicKey.E)

	/*
		//get encoding of modulus
		N := big.NewInt(0).Mul(p, q)
		s := base64.StdEncoding.EncodeToString(N.Bytes())
		fmt.Println(s)

		//get modulus from encoding
		b, err := base64.StdEncoding.DecodeString(s)
		newN := big.NewInt(0).SetBytes(b)
	*/
	/*
		//build packet details
		date := time.Date(2015, time.March, 14, 9, 26, 53, 58, time.UTC)
		packetPrivate := packet.NewRSAPrivateKey(date, &privateKey)
		packetPublic := packet.NewRSAPublicKey(date, privateKey.Public().(*rsa.PublicKey))
		name := "testName"
		comment := "testComment"
		email := "testEmail@test.com"
		userID := packet.NewUserId(name, comment, email)
		hash := sha512.New()
		var signature packet.Signature
		_ = signature.Sign(hash, packetPrivate, nil)
		var otherSignatures []*packet.Signature
		identity := openpgp.Identity{
			Name:          fmt.Sprintf("%s (%s) <%s>", name, comment, email),
			UserId:        userID,
			SelfSignature: &signature,
			Signatures:    otherSignatures}
		e := openpgp.Entity{
			PrimaryKey: packetPublic,
			PrivateKey: packetPrivate,
			Identities: map[string]*openpgp.Identity{identity.Name: &identity}}
		fmt.Println(e)
	*/
	/*
		w, err := armor.Encode(os.Stdout, "openpgp.PublicKeyType", nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer w.Close()
		e.Serialize(w)
	*/
	SassyPrimes()
}
