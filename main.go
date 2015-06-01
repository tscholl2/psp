package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"

	"github.com/codegangsta/cli"
	"github.com/tscholl2/psp/psp"
)

func main() {
	app := cli.NewApp()
	app.Name = "psp"
	app.Usage = `Generate fun RSA keys!

EXAMPLES:
    psp --name Mr.Science -m "////ThisIsAMessageWithBase64CharsSee////////" --primes`

	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "offset",
			Value: psp.TypePublicKeyPGP,
			Usage: `Number of bytes message is offset in key. Default: 37.
      For the message to appear in certain places requires a different offset.
      Available offsets are:
        PublicKeyPGP               = 1 (shortcut for 37)
        PrivateKeyPGP              = 2 (37)
        PublicKeyOpenssl           = 3 (15)
        PrivateKeyOpenssl          = 4 (36)
        CertificateRequest         = 5 (39)
        SelfSignedCertificate      = 6 (19)
        AuthoritySignedCertificate = 7 (54)
        Custom                     = 10..100`,
		},
		cli.StringFlag{
			Name:  "name, n",
			Value: "anonymous",
			Usage: "The name associated to the key.",
		},
		cli.StringFlag{
			Name:  "email, e",
			Value: "em@il",
			Usage: "The email associated to the key.",
		},
		cli.StringFlag{
			Name:  "message, m",
			Value: "",
			Usage: "A message to embed in your key. 64 characters is best.",
		},
		cli.IntFlag{
			Name:  "bits, b",
			Value: 2048,
			Usage: "Size of the key.",
		},
		cli.BoolTFlag{
			Name:  "primes, p",
			Usage: "Prints primes as well",
		},
		cli.BoolTFlag{
			Name:  "pem",
			Usage: "Outputs public/private key in PEM format.",
		},
		cli.BoolTFlag{
			Name:  "cert, c",
			Usage: "Also outputs a certificate request. Requires extra information.",
		},
	}

	app.Action = func(c *cli.Context) {
		msg := c.String("message")
		if msg == "" {
			msg = randomMessage()
		}
		k, err := psp.NewRsaKey(uint(c.Int("bits")), msg, c.Int("offset"))
		if err != nil {
			log.Fatalf("Error: %s", err.Error())
			return
		}
		e, err := psp.NewEntity(c.String("name"), "", c.String("email"), k)
		if err != nil {
			log.Fatalf("Error: %s", err.Error())
			return
		}
		pub, err := psp.ExportPublicPGP(e)
		if err != nil {
			log.Fatalf("Error: %s", err.Error())
			return
		}
		priv, err := psp.ExportPrivatePGP(e)
		if err != nil {
			log.Fatalf("Error: %s", err.Error())
			return
		}

		s := fmt.Sprintf("%s\n%s\n", pub, priv)
		if c.BoolT("primes") {
			s += fmt.Sprintf("p=\n%x\nq=\n%x\n", k.Primes[0], k.Primes[1])
		}

		fmt.Print(s)
	}

	app.Run(os.Args)
}

func randomMessage() string {
	table := []string{
		"////////////help/im/stuck/in/a/key/what/do/I/do/////////////////",
		"/////////////////whats/the/point/of/this////////////////////////",
		"/////////why/would/anyone/make/something/like/this//////////////",
		"//////personalized/pgp/keys/really/is/that/really/necessary/////",
		"/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
	}
	return table[rand.Intn(len(table))]
}
