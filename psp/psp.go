package psp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/tscholl2/goprime"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

//Key Types
const (
	PublicKeyPGP               = 1
	PrivateKeyPGP              = 2
	PublicKeyOpenssl           = 3
	PrivateKeyOpenssl          = 4
	CertificateRequest         = 5
	SelfSignedCertificate      = 6
	AuthoritySignedCertificate = 7
)

var one = big.NewInt(1)

// ExportPrivatePEM returns private RSA key for given identity
// in PEM suitable for use with openssl.
// To inspect a public key use
//   openssl pkey -in priv_file -noout -text
func ExportPrivatePEM(priv *rsa.PrivateKey) (string, error) {
	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil, //HEADERS WILL MAKE OPENSSL UNABLE TO LOAD KEY
		Bytes:   x509.MarshalPKCS1PrivateKey(priv),
	}
	w := bytes.NewBuffer(nil)
	err := pem.Encode(w, &block)
	if err != nil {
		return "", fmt.Errorf("Error writing PEM: %s", err)
	}
	return w.String(), nil
}

// ExportPublicPEM returns public RSA key for given identity
// in PEM suitable for use with openssl.
// To inspect a public key use
//   openssl pkey -in pub_file -noout -text -pubin
func ExportPublicPEM(pub *rsa.PublicKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("Error reading public key: %s", err)
	}
	block := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil, //HEADERS WILL MAKE OPENSSL UNABLE TO LOAD KEY
		Bytes:   b,
	}
	w := bytes.NewBuffer(nil)
	err = pem.Encode(w, &block)
	if err != nil {
		return "", fmt.Errorf("Error writing PEM: %s", err)
	}
	return w.String(), nil
}

// ExportCertificateRequest returns certificate signing
// request with the given entity/data encoded in PEM suitable for
// use with openssl and giving to a CA.
// To inspect a certifcate use
//    openssl x509 -in cert_file -noout -text
// To inspect a certificate request use
//   openssl req -in csr_file -noout -text
func ExportCertificateRequest(e *openpgp.Entity) (string, error) {
	var err error
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "domain.com",
			Country:            []string{"AU"},
			Province:           []string{"Some-State"},
			Locality:           []string{"MyCity"},
			Organization:       []string{"Company Ltd"},
			OrganizationalUnit: []string{"IT"},
		},
		EmailAddresses: []string{"test@email.com"},
	}
	key := e.PrivateKey.PrivateKey
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return "", fmt.Errorf("Error generating CSR: %s", err)
	}
	w := bytes.NewBuffer(nil)
	err = pem.Encode(w, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if err != nil {
		return "", fmt.Errorf("Error generating CSR: %s", err)
	}
	return w.String(), nil
}

// ExportPublicPGP returns ascii armored version of
// public key of the entity suitable for PGP.
func ExportPublicPGP(e *openpgp.Entity) (string, error) {
	var err error
	w := bytes.NewBuffer(nil)
	wr, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", fmt.Errorf("Error encoding Armor: %s", err)
	}
	err = e.Serialize(wr)
	if err != nil {
		return "", fmt.Errorf("Error serializing PubKey: %s", err)
	}
	err = wr.Close()
	if err != nil {
		return "", fmt.Errorf("Error closing writer: %s", err)
	}
	return w.String(), nil
}

// ExportPrivatePGP returns ascii armored version of
// private parts of the openpgp entity suitable
// for use with PGP.
func ExportPrivatePGP(e *openpgp.Entity) (string, error) {
	var err error
	w := bytes.NewBuffer(nil)
	wr, err := armor.Encode(w, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", fmt.Errorf("Error encoding Armor: %s", err)
	}
	err = e.SerializePrivate(wr, nil)
	if err != nil {
		return "", fmt.Errorf("Error serializing PrivateKey: %s", err)
	}
	err = wr.Close()
	if err != nil {
		return "", fmt.Errorf("Error closing writer: %s", err)
	}
	return w.String(), nil
}

// NewEntity returns a new openpgp entity for the given rsa key
// mostly to be used with NewRsaKey()
func NewEntity(name string, comment string, email string, priv *rsa.PrivateKey) (e *openpgp.Entity, err error) {
	currentTime := time.Date(2015, time.March, 14, 9, 26, 53, 58, time.UTC) //pi day!
	//currentTime := time.Now()

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
func NewRsaKey(bits uint, message string, keyType int) (*rsa.PrivateKey, error) {
	//initialize values
	var p, q, d, n *big.Int
	var err error

	priv := new(rsa.PrivateKey)
	priv.E = 65537

	if bits < 1024 {
		return nil, fmt.Errorf("Can't make a key < 1024 bits")
	}

SearchForPrimes:
	for {

		p, q, err = Primes(message, bits/2, keyType)
		if err != nil {
			return nil, fmt.Errorf("Error getting primes: %s", err.Error())
		}

		n = new(big.Int).Mul(p, q)
		pminus1 := new(big.Int).Sub(p, one)
		qminus1 := new(big.Int).Sub(q, one)
		totient := new(big.Int).Mul(pminus1, qminus1)

		if n.BitLen() != int(bits) {
			// This should happen less than the universe
			// exploding or something
			continue SearchForPrimes
		}

		g := new(big.Int)
		d = new(big.Int)
		e := big.NewInt(int64(priv.E))
		g.GCD(d, nil, e, totient)

		if g.BitLen() == 1 {
			// if gcd(d,e) == 1
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

	return priv, nil
}

// Primes returns p,q so that the base64
// encoding of N=p*q contains a sassy string.
// The bits option is the size of each prime
// so a 2048 bit key should call Primes for 1024
// bit primes. Also bits must be at least 1024
// and message must be exactly 64 bytes.
// keyType represents the type of pgp key that will
// be generated. The offset changes. Right now it
// supports:
//   keyType = 1 ---> pgp public key
//   keyType = 2 ---> pgp private key
//   keyType = 3 ---> openssl public key
//   keyType = 4 ---> openssl private key
//   keyType = 5 ---> certificate request
//   keyType = 6 ---> self signed certificate
//   keyType = 7 ---> authority signed cert
func Primes(message string, bits uint, keyType int) (p *big.Int, q *big.Int, err error) {
	//check input
	if bits < 1024 {
		//need 2048 bit keys to hold 64 char msg
		return nil, nil, fmt.Errorf("Bits must be at least 1024 to include message")
	}
	if len(message) != 64 {
		return nil, nil, fmt.Errorf("Message must be 64 bytes!")
	}
	var offset int
	switch keyType {
	case 1:
		offset = 37 // pgp public key
	case 2:
		offset = 37 // pgp private key
	case 3:
		offset = 15 // for openssl public key
	case 4:
		offset = 36 // for openssl private key
	case 5:
		offset = 39 // certificate request
	case 6:
		offset = 19 // for self signed certificate with THIS key probably
	case 7:
		offset = 54 // for authority signed certificates?
	default:
		offset = keyType //custom
		if offset < 10 || offset > 100 {
			return nil, nil, fmt.Errorf("Unknown type argument")
		}
	}

	// decode sass to bytes
	sass, _ := base64.StdEncoding.DecodeString(message)

	// geneterate primes
	p, err = rand.Prime(rand.Reader, int(bits))
	if err != nil {
		fmt.Errorf("Error generating primes: %s", err)
		return
	}
	q, err = rand.Prime(rand.Reader, int(bits))
	if err != nil {
		fmt.Errorf("Error generating primes: %s", err)
		return
	}
	N := new(big.Int).Mul(p, q)

	// insert sass
	b := N.Bytes()
	for i := 0; i < len(sass); i++ {
		b[i+offset] = sass[i]
	}
	N.SetBytes(b)

	// get a new q prime
	qtmp := new(big.Int).Div(N, p)
	q = goprime.NextPrime(qtmp)

	return
}
