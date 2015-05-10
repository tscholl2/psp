package psp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/tscholl2/psp/prime"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet" //I need this 'golang.org/x/crypto/openpgp'
)

var bigOne = big.NewInt(1)

// NewEntity returns a new openpgp entity for the given rsa key
// mostly to be used with NewRsaKey()
func NewEntity(name string, comment string, email string, privateKey *rsa.PrivateKey) *openpgp.Entity {
	//date := time.Date(2015, time.March, 14, 9, 26, 53, 58, time.UTC) //pi day!
	date := time.Now()
	packetPrivate := packet.NewRSAPrivateKey(date, privateKey)
	packetPublic := packet.NewRSAPublicKey(date, privateKey.Public().(*rsa.PublicKey))
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
	return &e
}

// NewRsaKey returns a new rsa private key
// with sassy primes
func NewRsaKey() (priv *rsa.PrivateKey, err error) {
	//initialize values
	var p, q, d, n *big.Int
	priv = new(rsa.PrivateKey)
	priv.E = 65537
	bits := 2048

SearchForPrimes:
	for {

		p, q, err = Primes()
		if err != nil {
			fmt.Errorf("Error getting primes: %s", err.Error())
			return
		}

		n = new(big.Int).Mul(p, q)
		pminus1 := new(big.Int).Sub(p, bigOne)
		qminus1 := new(big.Int).Sub(q, bigOne)
		totient := new(big.Int).Mul(pminus1, qminus1)

		if n.BitLen() != bits {
			// This should happen less than the universe
			// exploding or something
			continue SearchForPrimes
		}

		g := new(big.Int)
		d = new(big.Int)
		y := new(big.Int)
		e := big.NewInt(int64(priv.E))
		g.GCD(d, y, e, totient)

		if g.Cmp(bigOne) == 0 {
			if d.Sign() < 0 {
				d.Add(d, totient)
			}

			break
		}
	}

	priv.D = d
	priv.Primes = []*big.Int{p, q}
	priv.N = new(big.Int).Mul(p, q)
	priv.Precompute()

	return
}

// Primes returns p,q so that the
// base64 encoding of N=p*q contains a
// sassy string
func Primes() (p *big.Int, q *big.Int, err error) {
	// decode sass to bytes
	// important to be 64 characters long
	s := "/this/string/is/64/characters/long/dont/you/see/that/please/see/"
	sass, _ := base64.StdEncoding.DecodeString(s)

	// geneterate primes
	p, err = rand.Prime(rand.Reader, 1024) //2048 bit keys can hold 64 char msg
	if err != nil {
		fmt.Errorf("Error generating primes: %s", err)
		return
	}
	q, err = rand.Prime(rand.Reader, 1024)
	if err != nil {
		fmt.Errorf("Error generating primes: %s", err)
		return
	}
	N := new(big.Int).Mul(p, q)

	//fmt.Println("OLD N")
	//fmt.Println(base64.StdEncoding.EncodeToString(N.Bytes()))

	// insert sass
	b := N.Bytes()
	offset := 36 //make sass appear on a line of its own
	for i := 0; i < len(sass); i++ {
		b[i+offset] = sass[i]
	}
	N.SetBytes(b)

	// get a new q prime
	qtmp := new(big.Int).Div(N, p)
	q = prime.NextPrime(qtmp)

	//fmt.Println("FINAL N")
	//fmt.Println(base64.StdEncoding.EncodeToString(N.Mul(p, q).Bytes()))

	return
}
