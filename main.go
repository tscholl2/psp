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
	app.Name = "PSP"
	app.Usage = "Generate fun RSA keys!"

	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "offset",
			Value: psp.TypePublicKeyPGP,
			Usage: "Number of bytes message is offset in key. Default: 37.",
		},
		cli.StringFlag{
			Name:  "name, n",
			Value: "Anyonomous",
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
			Usage: "A message to embed in your key at specified offset. 64 characters is best.",
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
