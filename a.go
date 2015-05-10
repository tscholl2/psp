package main

import (
	"fmt"
	"math/big"
)

func main() {
	fmt.Println("hello")
	q := big.NewInt(17)
	fmt.Printf("p = %d\nnextprime = %d\n", q, NextPrime(q))
	q = big.NewInt(170)
	fmt.Printf("p = %d\nnextprime = %d\n", q, NextPrime(q))
	q = big.NewInt(1700)
	fmt.Printf("p = %d\nnextprime = %d\n", q, NextPrime(q))
}

var smallModulous = 128

func gcd(u int, v int) int {
	if u < 0 {
		return gcd(-u, v)
	}
	if u == 0 {
		return v
	}
	return gcd(v%u, u)
}

// nextSmallPrime returns the next small int
// assume n < smallModulous
func nextSmallPrime(n int) (p int) {
	if n > smallModulous || n < 0 {
		panic("n is not smaller than the modulous!")
	}
	for p = n + 1; gcd(smallModulous, p) != 1; p++ { //deal with wrap around
	}
	return
}

// NextPrime returns a number, p, with p>=n
// and high probability that p is the next prime
// occuring after n
func NextPrime(n *big.Int) (p *big.Int) {
	p = n //change to a copy //OPIMTIMZE
	for i := 0; i < 5; i++ {
		fmt.Printf("got p=%d\n", p)
		mod := int(new(big.Int).Mod(n, big.NewInt(int64(smallModulous))).Int64())
		fmt.Printf("mod=%d\n", mod)
		next := nextSmallPrime(mod)
		fmt.Printf("next=%d\n", next)
		p.Add(p, big.NewInt(int64(next-mod)))
		fmt.Printf("new p=%d\n", p)
		if BPSW(p) {
			return
		}
	}
	panic("unable to find enext prime!")
}

// BPSW runs the Baillie-PSW primality test
// for more see http://www.trnicely.net/misc/bpsw.html
func BPSW(p *big.Int) bool {
	// Step 1: check  all small primes
	if p.BitLen() == 1 {
		return false // 0 and 1 are not primes!
	}
	if p.Bit(0) == 0 {
		return false
	}

	// Step 2: Miller-Rabin test base 2
	if !p.ProbablyPrime(20) {
		// If it returns true, x is prime with probability 1 - 1/4^n
		return false
	}

	// Step 3: Lucas-Selfridge test

	//
	// TODO
	//

	return true
}

/*
BPSW: http://www.trnicely.net/misc/bpsw.html
Process all N < 3 and all even N.
Check N for any small prime divisors p < 1000.
Perform a Miller-Rabin (strong probable prime) test, base 2, on N.
Perform a (standard or strong) Lucas-Selfridge test on N, using Lucas
    sequences with the parameters suggested by Selfridge.
*/
