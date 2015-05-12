package prime

import (
	"crypto/rand"
	"math"
	"math/big"
)

const (
	primesProduct8  = 0x69               // Π {p ∈ primes, 2 < p <= 7}
	primesProduct16 = 0x3AA7             // Π {p ∈ primes, 2 < p <= 13}
	primesProduct32 = 0xC0CFD797         // Π {p ∈ primes, 2 < p <= 29}
	primesProduct64 = 0xE221F97C30E94E1D // Π {p ∈ primes, 2 < p <= 53}
)

var (
	primes8  = []uint8{3, 5, 7}                         //product is 8 bits
	primes16 = []uint8{3, 5, 7, 11, 13}                 //product is 16 bits
	primes32 = []uint8{3, 5, 7, 11, 13, 17, 19, 23, 29} //product is 32 bits
	primes64 = []uint8{3, 5, 7, 11, 13, 17, 19, 23, 29,
		31, 37, 41, 43, 47, 53} //product is 64 bits
	primesUnder1000 = []uint16{
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
		67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
		139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
		223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
		293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
		383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
		463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
		569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643,
		647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
		743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
		839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
		941, 947, 953, 967, 971, 977, 983, 991, 997}
	smallPrimes             = []uint8{2, 3, 5, 7}
	smallModulous     int64 = 210 // = 2*3*5*7
	bigSmallModulous  *big.Int
	diffToNextCoprime []*big.Int
	bigZero           = big.NewInt(0)
	bigOne            = big.NewInt(1)
	bigTwo            = big.NewInt(2)
)

//precomputations
func init() {
	//set big version
	bigSmallModulous = big.NewInt(smallModulous)
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
	var mod = new(big.Int)
	var diff *big.Int
	p = new(big.Int).Set(n)
	for {
		if BPSW(p) {
			return
		}
		mod.Mod(p, bigSmallModulous)
		diff = diffToNextCoprime[int(mod.Int64())]
		p.Add(p, diff)
	}
}

// checkSmallPrimes returns true if N is
// divisible by any prime in a small pre-set
// list of primes up to 8,16,32, or 64 bits
func checkSmallPrimes(N *big.Int, bits uint8) bool {
	// Check N is non-negative
	if N.Sign() < 0 { // TODO: see if this makes a difference in speed, modding out may be faster with positive?
		return checkSmallPrimes(new(big.Int).Abs(N), bits)
	}
	// Sanity checks
	if N.BitLen() == 1 {
		// 0 and 1 are not primes!
		return false
	}
	if N.Bit(0) == 0 {
		// check if even
		return false
	}
	//TODO try and just mod out by primeProductxx and check divisibility with uint8's
	// parse input
	var primes []uint8
	switch bits {
	case 8:
		primes = primes8
	case 16:
		primes = primes16
	case 32:
		primes = primes32
	case 64:
		primes = primes64
	default:
		panic("Unknown bits exception!")
	}
	for _, p := range primes { // TODO: 64 can be changed for speed?
		//check all small primes in some range
		// TODO: make a thing holding big versions of p
		// or check 0 by looking at first p-many bytes
		if new(big.Int).Mod(N, big.NewInt(int64(p))).Cmp(bigZero) == 0 {
			return false
		}
	}
	return true
}

// BPSW runs the Baillie-PSW primality test
// so returns true if probably a prime, otherwise false
// for more see http://www.trnicely.net/misc/bpsw.html
func BPSW(N *big.Int) bool {

	/*
		BPSW: http://www.trnicely.net/misc/bpsw.html
		Process all N < 3 and all even N.
		Check N for any small prime divisors p < 1000.
		Perform a Miller-Rabin (strong probable prime) test, base 2, on N.
		Perform a (standard or strong) Lucas-Selfridge test on N, using Lucas
		    sequences with the parameters suggested by Selfridge.
	*/

	// Step 0: small case
	if N.BitLen() < 9 {
		n := uint16(N.Int64())
		for _, p := range primesUnder1000 {
			if n == p {
				return true
			}
		}
		return false
	}

	// Step 1: check  all small primes
	for _, p := range primesUnder1000 {
		//check all small primes in some range
		//note N is big so it wont be = to any p
		// TODO make a thing holding big versions of p?
		if new(big.Int).Mod(N, big.NewInt(int64(p))).Cmp(bigZero) == 0 {
			return false
		}
	}

	// Step 2: Miller-Rabin test base 2
	if !N.ProbablyPrime(20) {
		// If it returns true, x is prime with probability 1 - 1/4^n
		return false
	}

	// Step 3: Lucas-Selfridge test

	//
	// TODO lucas-selfridge test
	//

	return true
}

// StrongLucasSelfridgeTest takes an integer N
// and returns true if N is prime or a strong
// Lucas-Selfridge pseudoprime and false otherwise
// see http://www.trnicely.net/misc/bpsw.html
func StrongLucasSelfridgeTest(N *big.Int) bool {
	//Step 0: parse input
	if N.Sign() <= 0 {
		if N.Sign() == 0 {
			// zero is not prime
			return false
		}
		// Check N is positive
		return StrongLucasSelfridgeTest(new(big.Int).Abs(N))
	}

	// Step 1: check  all small primes
	if N.BitLen() == 1 {
		// 0 and 1 are not primes!
		return false
	}
	for _, p := range primesUnder1000 {
		if new(big.Int).Mod(N, big.NewInt(int64(p))).Cmp(bigZero) == 0 {
			return false
		}
	}

	// Step 2: check if N is a perfect square
	if IsSquare(N) {
		return false
	}

	// Step 3: find the first element D in the
	// sequence {5, -7, 9, -11, 13, ...} such that
	// Jacobi(D,N) = -1 (Selfridge's algorithm).

	return false
}

// JacobiSymbol returns the jacobi symbol of
// N over D, see http://en.wikipedia.org/wiki/Jacobi_symbol
func JacobiSymbol(N *big.Int, D *big.Int) int {
	//easy cases
	if D.Cmp(bigZero) == 0 {
		panic("JacobiSymbol over 0 Error!")
	}
	if D.Cmp(bigOne) == 0 || N.Cmp(bigOne) == 0 {
		return 1
	}
	if new(big.Int).GCD(nil, nil, N, D).Cmp(bigOne) != 0 {
		return 0
	}

	//rest of the stuff
	j := 1
	n := new(big.Int).Set(N)
	d := new(big.Int).Set(D)
Step1:
	for {
		// Step 1: Reduce the numerator mod the denominator
		n = new(big.Int).Mod(n, d)

		//fmt.Printf("step 1, \nn = %d\nd = %d\nj = %d\n", n, d, j)

		// Step 2: extract factors of 2
		var symMod2 int
		switch int(new(big.Int).Mod(d, big.NewInt(8)).Int64()) { // TODO: mod 8 is taking first byte?
		case 1, 7:
			symMod2 = 1
		case 3, 5:
			symMod2 = -1
		}
		for n.Bit(0) == 0 {
			n.Div(n, bigTwo) // TODO %2 is bit shift?
			j = j * symMod2
		}

		//fmt.Printf("step 2, \nn = %d\nd = %d\nj = %d\n", n, d, j)

		// Step 3: check numerator and gcd
		if n.Cmp(bigOne) == 0 {
			return j
		}
		if new(big.Int).GCD(nil, nil, n, d).Cmp(bigOne) != 0 {
			return 0
		}

		//fmt.Printf("step 3, \nn = %d\nd = %d\nj = %d\n", n, d, j)

		// Step 4: flip and go back to step 1
		if int(new(big.Int).Mod(n, big.NewInt(4)).Int64()) != 1 { // n = 3 mod 4
			if int(new(big.Int).Mod(d, big.NewInt(4)).Int64()) != 1 { // d = 3 mod 4
				j = -1 * j
			}
		}
		tmp := new(big.Int).Set(n)
		n.Set(d)
		d.Set(tmp)

		//fmt.Printf("step 4, \nn = %d\nd = %d\nj = %d\n", n, d, j)

		continue Step1
	}
}

// IsSquare returns true if N is a perfect
// square, that is N = m^2 for some positive
// integer m. Basically applies newtons method
func IsSquare(N *big.Int) bool {
	// Step -1: check inputs
	if N.Sign() <= 0 {
		// 0 is a square
		if N.Sign() == 0 {
			return true
		}
		// negative numbers are not
		return false
	}
	// Step 0: Easy case
	if N.BitLen() < 64 {
		n := N.Int64()
		a := int64(math.Sqrt(float64(n)))
		if a*a == n {
			return true
		}
		return false
	}

	// Step 1: make a random guess for sqrt
	// with the right order of magnitude
	bigTwo := big.NewInt(2)
	bytes := make([]byte, N.BitLen()/16)
	rand.Read(bytes)
	x := new(big.Int).SetBytes(bytes)
	y := new(big.Int)

	// Step 2: run newtons method until it
	// stabilized (same value or one off), see wiki article
	// http://en.wikipedia.org/wiki/Integer_square_root
	// convergence is quadratic so shouldn't take long
	// if it doesn't converge it should alternate between +-1
	// so return false in that case
	for i := 0; i < N.BitLen()/2+5; i++ {
		y.Div(y.Add(x, y.Div(N, x)), bigTwo) // Set y = [(x + [N/x])/2] // TODO: division by 2 is bit shift?
		if x.Cmp(y) == 0 {
			return true
		}
		x.Set(y)
	}

	return false
}
