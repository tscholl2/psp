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
	TypePublicKeyPGP               = 1
	TypePrivateKeyPGP              = 2
	TypePublicKeyOpenssl           = 3
	TypePrivateKeyOpenssl          = 4
	TypeCertificateRequest         = 5
	TypeSelfSignedCertificate      = 6
	TypeAuthoritySignedCertificate = 7
)

// ExportPrivatePEM returns private RSA key
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

// ExportPublicPEM returns public RSA key
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
		Headers: nil, //headers make openssl unable to load key
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
	// TODO - make template an input with some defaults
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
	//currentTime := time.Date(2015, time.March, 14, 9, 26, 53, 58, time.UTC) //pi day!
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
			Hash:         crypto.SHA1,
			// these are the same defaults as standard gpg keys
			PreferredHash: []uint8{8, 2, 9, 10, 11},
			/*
				1          - MD5 [HAC]                             "MD5"
				2          - SHA-1 [FIPS180]                       "SHA1"
				3          - RIPE-MD/160 [HAC]                     "RIPEMD160"
				4          - Reserved
				5          - Reserved
				6          - Reserved
				7          - Reserved
				8          - SHA256 [FIPS180]
			*/
			PreferredCompression: []uint8{2, 3, 1},
			/*
				0          - Uncompressed
				1          - ZIP [RFC1951]
				2          - ZLIB [RFC1950]
				3          - BZip2 [BZ2]
				100 to 110 - Private/Experimental algorithm
			*/
			PreferredSymmetric: []uint8{9, 8, 7, 3, 2},
			/*
				0          - Plaintext or unencrypted data
				1          - idea [idea]
				2          - TripleDES (DES-EDE, [SCHNEIER] [HAC] -
							168 bit key derived from 192)
				3          - CAST5 (128 bit key, as per [RFC2144])
				4          - Blowfish (128 bit key, 16 rounds) [BLOWFISH]
				5          - Reserved
				6          - Reserved
				7          - AES with 128-bit key [AES]
				8          - AES with 192-bit key
				9          - AES with 256-bit key
				10         - Twofish with 256-bit key [TWOFISH]
				100 to 110 - Private/Experimental algorithm
			*/
			IsPrimaryId:               &isPrimaryID,
			FlagsValid:                true,
			FlagSign:                  true,
			FlagCertify:               true,
			FlagEncryptCommunications: true,
			FlagEncryptStorage:        true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
		},
	}
	e.Identities[uid.Id].SelfSignature.SignKey(e.PrimaryKey, e.PrivateKey, nil)
	e.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, e.PrimaryKey, e.PrivateKey, nil)
	return
}

// NewRsaKey returns a new rsa private key
// using the primes generated from Primes()
// it is pretty much a copy of crypto/rsa.GenerateKey()
func NewRsaKey(bits uint, message string, keyType int) (priv *rsa.PrivateKey, err error) {
	var p, q, d, N *big.Int
	d = new(big.Int)
	priv = new(rsa.PrivateKey)
	priv.E = 65537
SearchForPrimes:
	for {

		//collect some primes
		p, q, err = Primes(message, bits/2, keyType)
		if err != nil {
			err = fmt.Errorf("Error getting primes: %s", err)
			return
		}

		// compute rsa modulous and private keys
		N = new(big.Int).Mul(p, q)
		if N.BitLen() != int(bits) {
			continue SearchForPrimes
		}

		pminus1 := new(big.Int).Sub(p, big.NewInt(1))
		qminus1 := new(big.Int).Sub(q, big.NewInt(1))
		totient := new(big.Int).Mul(pminus1, qminus1)
		gcd := new(big.Int).GCD(d, nil, big.NewInt(int64(priv.E)), totient)

		if gcd.BitLen() == 1 {
			// if gcd(d,e) == 1
			if d.Sign() < 0 {
				// take positive residue of d mod totient
				d.Add(d, totient)
			}
			break
		}
	}

	// build private key
	priv.D = d
	priv.Primes = []*big.Int{p, q}
	priv.N = N
	priv.Precompute()

	return
}

// Primes returns p,q so that the base64
// encoding of N=p*q contains the given message.
// The bits option is the size of each prime
// so a 2048 bit key should call Primes(string,1024,type)
// Note: It takes a 2048 bit key (so 1024 primes)
// to have a message with 64 characters.
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
//   keyType = anything else ---> custom offset
func Primes(message string, bits uint, keyType int) (p *big.Int, q *big.Int, err error) {
	//check input
	/*
		if bits < 1024 {
			//need 2048 bit keys to hold 64 char msg
			err = fmt.Errorf("Bits must be at least 1024 bit to include message")
			return
		}
		if len(message) != 64 {
			err = fmt.Errorf("Message must be 64 bytes!")
			return
		}
	*/
	var offset int
	switch keyType {
	case TypePublicKeyPGP:
		offset = 37 // pgp public key
	case TypePrivateKeyPGP:
		offset = 37 // pgp private key
	case TypePublicKeyOpenssl:
		offset = 15 // for openssl public key
	case TypePrivateKeyOpenssl:
		offset = 36 // for openssl private key
	case TypeCertificateRequest:
		offset = 39 // certificate request
	case TypeSelfSignedCertificate:
		offset = 19 // for self signed certificate with THIS key probably
	case TypeAuthoritySignedCertificate:
		offset = 54 // for authority signed certificates?
	default:
		offset = keyType //custom
		if offset < 10 || offset > 100 {
			err = fmt.Errorf("Unknown type argument")
			return
		}
	}

	// decode message to bytes
	// then when it is encoded back to b64
	// it will display the correct characters
	b64msg, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		err = fmt.Errorf("Error decoding message: %s", err)
		return
	}

	// geneterate primes
	p, err = rand.Prime(rand.Reader, int(bits))
	if err != nil {
		err = fmt.Errorf("Error generating primes: %s", err)
		return
	}
	q, err = rand.Prime(rand.Reader, int(bits))
	if err != nil {
		err = fmt.Errorf("Error generating primes: %s", err)
		return
	}
	N := new(big.Int).Mul(p, q)

	// insert message
	b := N.Bytes()
	for i := 0; i < len(b64msg); i++ {
		b[i+offset] = b64msg[i]
	}
	N.SetBytes(b)

	// get a new q prime
	qtmp := new(big.Int).Div(N, p)
	q = goprime.NextPrime(qtmp)

	return
}
