package prime

import "math/big"

var smallPrimes = []uint8{2, 3, 5, 7}
var smallModulous uint8 //important that 2*3*5*7 is 8 bits!
var bigSmallModulous *big.Int
var diffToNextCoprime []*big.Int

//precomputations
func init() {
	//set smallModulous to be product of small primes
	smallModulous = 1
	for _, p := range smallPrimes {
		smallModulous = smallModulous * p
	}
	//set big version
	bigSmallModulous = big.NewInt(int64(smallModulous))
	//calculate the diff table for coprimes
	diffToNextCoprime = make([]*big.Int, smallModulous)
	diffToNextCoprime[0] = new(big.Int).SetInt64(1)
	var d int
	for i := 1; i < int(smallModulous); i++ {
		if gcd(i, int(smallModulous)) == 1 {
			d = 1
		} else {
			d = 0
		}
		for ; gcd(i+d, int(smallModulous)) != 1; d++ {
		}
		diffToNextCoprime[i] = new(big.Int).SetInt64(int64(d))
	}
}

func gcd(u int, v int) int {
	if u < 0 {
		return gcd(-u, v)
	}
	if u == 0 {
		return v
	}
	return gcd(v%u, u)
}

// NextPrime returns a number, p, with p>=n
// and high probability that p is the next prime
// occuring after n
func NextPrime(n *big.Int) (p *big.Int) {
	var bigMod = new(big.Int)
	var diff *big.Int
	p = new(big.Int).Set(n)
	for {
		if BPSW(p) {
			return
		}
		bigMod.Mod(p, bigSmallModulous)
		diff = diffToNextCoprime[int(bigMod.Int64())]
		p.Add(p, diff)
	}
}

// BPSW runs the Baillie-PSW primality test
// so returns true if probably a prime, otherwise false
// for more see http://www.trnicely.net/misc/bpsw.html
func BPSW(p *big.Int) bool {

	/*
		BPSW: http://www.trnicely.net/misc/bpsw.html
		Process all N < 3 and all even N.
		Check N for any small prime divisors p < 1000.
		Perform a Miller-Rabin (strong probable prime) test, base 2, on N.
		Perform a (standard or strong) Lucas-Selfridge test on N, using Lucas
		    sequences with the parameters suggested by Selfridge.
	*/

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
	// TODO lucas-selfridge test
	//

	return true
}
