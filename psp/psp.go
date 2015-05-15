package psp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/tscholl2/goprime"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

var bigOne = big.NewInt(1)

const (
	// PublicKeyType is the armor type for a PGP public key.
	PublicKeyType = "SASSY PGP PUBLIC KEY"
	// PrivateKeyType is the armor type for a PGP private key.
	PrivateKeyType = "SASSY PGP PRIVATE KEY"
	// SignatureType is the armor type for a PGP signature.
	SignatureType = "SASSY PGP SIGNATURE"
)

func Serialize(e *openpgp.Entity) string {
	var buffer bytes.Buffer
	w, err := armor.Encode(&buffer, PrivateKeyType, nil)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer w.Close()
	e.Serialize(w)
	return buffer.String()
}

//Create ASscii Armor from openpgp.Entity
func ArmorUp(pubEnt *openpgp.Entity) (asciiEntity string) {
	gotWriter := bytes.NewBuffer(nil)
	wr, errEncode := armor.Encode(gotWriter, openpgp.PublicKeyType, nil)
	if errEncode != nil {
		fmt.Println("Encoding Armor ", errEncode.Error())
		return
	}
	errSerial := pubEnt.Serialize(wr)
	if errSerial != nil {
		fmt.Println("Serializing PubKey ", errSerial.Error())
	}
	errClosing := wr.Close()
	if errClosing != nil {
		fmt.Println("Closing writer ", errClosing.Error())
	}
	asciiEntity = gotWriter.String()
	return
}

// NewEntity returns a new openpgp entity for the given rsa key
// mostly to be used with NewRsaKey()
func NewEntity(name string, comment string, email string, priv *rsa.PrivateKey) (e *openpgp.Entity, err error) {
	//date := time.Date(2015, time.March, 14, 9, 26, 53, 58, time.UTC) //pi day!
	currentTime := time.Now()

	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		err = errors.InvalidArgumentError("user id field contained invalid characters")
		return
	}

	e = &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(currentTime, &priv.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(currentTime, priv),
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryID := true
	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         crypto.SHA256,
			IsPrimaryId:  &isPrimaryID,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}
	e.Identities[uid.Id].SelfSignature.SignKey(e.PrimaryKey, e.PrivateKey, nil)
	e.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, e.PrimaryKey, e.PrivateKey, nil)
	return

}

// NewRsaKey returns a new rsa private key
// using the primes generated from Primes()
// it is pretty much a copy of crypto/rsa.GenerateKey()
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

// Primes returns p,q so that the base64
// encoding of N=p*q contains a sassy string
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
	offset := 37 //make sass appear on a line of its own
	for i := 0; i < len(sass); i++ {
		b[i+offset] = sass[i]
	}
	N.SetBytes(b)

	// get a new q prime
	qtmp := new(big.Int).Div(N, p)
	q = goprime.NextPrime(qtmp)

	//fmt.Println("FINAL N")
	//fmt.Println(base64.StdEncoding.EncodeToString(N.Mul(p, q).Bytes()))

	return
}
