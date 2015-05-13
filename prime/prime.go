package prime

import (
	"crypto/rand"
	"fmt"
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

	// Step 1: check  all small primes
	for _, p := range primesUnder1000 {
		//check all small primes in some range
		//note N is big so it wont be = to any p
		// TODO make a thing holding big versions of p?
		if new(big.Int).Mod(N, big.NewInt(int64(p))).Sign() == 0 {
			// if n = 0 mod p
			if N.BitLen() < 9 && N.Int64() == int64(p) {
				// if n = p
				return true
			}
			return false
		}
	}

	// Step 2: Miller-Rabin test
	// returns false if composite
	if !MillerRabin(N, 2) {
		return false
	}

	// Step 3: Lucas-Selfridge test
	// returns false if composite
	if !StrongLucasSelfridgeTest(N) {
		return false
	}

	return true
}

// MillerRabin returns true if N is a MR
// psuedoprime in base a, i.e., it returns
// false if a is a witness for compositeness
// of N or N os a strong pseudoprime base a
// use .ProbablyPrime if you want to do a lot
// of random tests, this is for one specific
// base value.
func MillerRabin(N *big.Int, a int64) bool {
	// Step 0: parse input
	if N.Sign() <= 0 || a < 2 {
		panic("Cannot run MR on non-positives!")
	}
	A := big.NewInt(a)
	if new(big.Int).GCD(nil, nil, N, A).Cmp(bigOne) != 0 {
		return false
	}

	// Step 1: factors 2s out of n-1
	var s uint64
	d := new(big.Int).Sub(N, bigOne)
	for d.Bit(0) == 0 {
		s++
		d.Rsh(d, 1)
	}

	// Step 2: compute powers
	Ad := new(big.Int).Exp(A, d, N)
	negOne := new(big.Int).Sub(N, bigOne)
	if Ad.Cmp(bigOne) == 0 || Ad.Cmp(negOne) == 0 {
		return true
	}
	var r uint64
	for r = 1; r < s; r++ {
		Ad.Exp(Ad, bigTwo, N)
		if Ad.Cmp(negOne) == 0 {
			return true
		}
	}

	// Step 3: a is not a witness
	return false

}

// StrongLucasSelfridgeTest takes an integer N
// and returns true if N is prime or a strong
// Lucas-Selfridge pseudoprime and false otherwise
// see http://www.trnicely.net/misc/bpsw.html
func StrongLucasSelfridgeTest(N *big.Int) bool {

	//fmt.Printf("Step 0: parsing input\nN = %d\n", N)

	// Step 0: parse input
	if N.Sign() <= 0 {
		panic("Cannot run LS on non-positives!")
	}

	//fmt.Println("Step 1: checking if square")

	// Step 1: check if N is a perfect square
	if IsSquare(N) {
		return false
	}

	//fmt.Println("Step 2: looking for D (Jacobi Symbol)")

	// Step 2: find the first element D in the
	// sequence {5, -7, 9, -11, 13, ...} such that
	// Jacobi(D,N) = -1 (Selfridge's algorithm).
	D := big.NewInt(5)
	for JacobiSymbol(D, N) != -1 {
		//fmt.Printf("trying, N=%d\n D = %d\n", N, D)
		d := new(big.Int).Add(new(big.Int).Abs(D), bigTwo)
		if D.Sign() > 0 {
			d.Neg(d)
		}
		D.Set(d)
	}
	// Set some variables
	P := big.NewInt(1) // Selfridge's choice, also set on wiki package
	// http://en.wikipedia.org/wiki/Lucas_pseudoprime#Implementing_a_Lucas_probable_prime_test
	Q := new(big.Int).Mod(new(big.Int).Div(new(big.Int).Sub(bigOne, D), big.NewInt(4)), N)
	//check for some common factors
	if new(big.Int).GCD(nil, nil, N, Q).Cmp(bigOne) != 0 {
		return false
	}

	//fmt.Printf("D = %d\nP = %d\nQ = %d\n", D, P, Q)
	//fmt.Println("Step 3: factor out 2's (d,s)")

	// Step 3: Find d so N+1 = 2^s*d with d odd
	d := new(big.Int).Add(N, bigOne)
	var s uint64 //this is the exponent of 2, so if overflows than you have more memory than the starship Enterprise
	for d.Bit(0) == 0 {
		d.Rsh(d, 1) // TODO right shift all at once --> MUCH faster
		s++
	}

	//fmt.Printf("d = %d\ns = %d\n", d, s)
	//fmt.Println("Step 4: looking for U_k,V_k,Q^k (Lucas #s)")

	// Step 4: Calculate the V's
	/*
		The strong Lucas-Selfridge test then returns N as a strong
		Lucas probable prime (slprp) if any of the following
		conditions is met: U_d=0, V_d=0, V_2d=0, V_4d=0, V_8d=0,
		V_16d=0, ..., etc., ending with V_{2^(s-1)*d}=V_{(N+1)/2}=0
		(all equalities mod N).
	*/
	div2 := new(big.Int).ModInverse(bigTwo, N)
	Uk := big.NewInt(0)            // U_0 = 0
	Vk := new(big.Int).Set(bigTwo) // V_0 = 2
	Qk := new(big.Int).Set(bigOne) // Q^0 = 1
	// follow repeated squaring algorithm
	for i := d.BitLen() - 1; i > -1; i-- {
		//double everything
		Uk.Mod(new(big.Int).Mul(Uk, Vk), N) // now U_{2k}
		Vk.Mod(new(big.Int).Sub(new(big.Int).Mul(Vk, Vk), new(big.Int).Mul(bigTwo, Qk)), N)
		Qk.Mod(new(big.Int).Mul(Qk, Qk), N) // now Q^{2k}
		// check small bit
		if d.Bit(i) == 1 {
			// increment by 1
			Qk.Mod(new(big.Int).Mul(Qk, Q), N)
			PxUk := new(big.Int).Mod(new(big.Int).Mul(P, Uk), N)
			DxUk := new(big.Int).Mod(new(big.Int).Mul(D, Uk), N)
			PxVk := new(big.Int).Mod(new(big.Int).Mul(P, Vk), N)
			Uk.Mod(new(big.Int).Mul(new(big.Int).Add(PxUk, Vk), div2), N)   // TODO check if even then bit shift instead of mul by div2
			Vk.Mod(new(big.Int).Mul(new(big.Int).Add(DxUk, PxVk), div2), N) // TODO check if even then bit shift instead of mul by div2
		}
	}

	//fmt.Printf("U_d = %d\nV_d = %d\nQ^d = %d\n", Uk, Vk, Qk)

	// U_k, V_k, Q^k are now all with k=d
	if Uk.Sign() == 0 {
		// if U_d = 0
		return true
	}
	// Now we look at powers V_{{2^r}d} for r = 0..s-1
	var r uint64
	for r = 0; r < s; r++ {
		if Vk.Sign() == 0 {
			// if V_{2^rd} = 0
			return true
		}
		Vk.Mod(new(big.Int).Sub(new(big.Int).Mul(Vk, Vk), new(big.Int).Mul(bigTwo, Qk)), N)
		Qk.Mod(new(big.Int).Mul(Qk, Q), N)
	}

	//fmt.Println("Step 5: no pass, return false")

	// Step 5: return false because it didn't pass the test
	return false
}

// JacobiSymbol returns the jacobi symbol of
// N (numerator) over D denominator
// see http://en.wikipedia.org/wiki/Jacobi_symbol
func JacobiSymbol(N *big.Int, D *big.Int) int {
	//Step 0: parse input / easy cases
	if D.Sign() <= 0 {
		// we will assume D is positive
		// wolfram is ok with negative denominator
		// im not sure what is standard though
		panic("JacobiSymbol over non-positive Error!")
	}
	if D.Cmp(bigOne) == 0 || N.Cmp(bigOne) == 0 {
		return 1
	}
	if new(big.Int).GCD(nil, nil, new(big.Int).Abs(N), D).Cmp(bigOne) != 0 {
		return 0
	}

	//rest of the stuff
	j := 1
	n := new(big.Int).Set(N)
	d := new(big.Int).Set(D)
Step1:
	for {
		// Step 1: Reduce the numerator mod the denominator
		// TODO switch n with n - d if that is smaller abs and use easy
		// formula for (-1 / d)
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
		for n.Bit(0) == 0 { //TODO count bits to shift and do all at once
			n.Rsh(n, 1)
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

// Jacobi returns the Jacobi symbol (x/y), either +1, -1, or 0.
// The y argument must be an odd integer.
// Stole from commit
// https://github.com/golang/go/blob/ac6158828870abcbf7d9ef86c89569a2a7d7020c/src/math/big/int.go
func Jacobi(x, y *big.Int) int {
	if len(y.Bits()) == 0 || y.Bits()[0]&1 == 0 {
		panic(fmt.Sprintf("big: invalid 2nd argument to Int.Jacobi: need odd integer but got %x", y))
	}

	// We use the formulation described in chapter 2, section 2.4,
	// "The Yacas Book of Algorithms":
	// http://yacas.sourceforge.net/Algo.book.pdf

	var a, b, c *big.Int
	a.Set(x)
	b.Set(y)
	j := 1

	if b.Sign() < 0 {
		if a.Sign() < 0 {
			j = -1
		}
		b.Abs(b)
	}

	for {
		if len(b.Bits()) == 1 && b.Bit(0) == 1 {
			return j
		}
		if len(a.Bits()) == 0 {
			return 0
		}
		a.Mod(a, b)
		if len(a.Bits()) == 0 {
			return 0
		}
		// a > 0

		// handle factors of 2 in 'a'
		s := a.Bits().trailingZeroBits()
		if s&1 != 0 {
			bmod8 := b.Bits()[0] & 7
			if bmod8 == 3 || bmod8 == 5 {
				j = -j
			}
		}
		c.Rsh(a, s) // a = 2^s*c

		// swap numerator and denominator
		if b.Bits()[0]&3 == 3 && c.Bits()[0]&3 == 3 {
			j = -j
		}
		a.Set(b)
		b.Set(c)
	}
}

func trailingZeroBits(x *big.Int) (i uint) { //TODO fix, use lookup table for words
	if x.Sign() < 0 {
		panic("unknown bits of negative")
	}
	for i > uint(x.BitLen()) && x.Bit(int(i)) != 1 {
		i++
	}
	return
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
	d := N.BitLen()
	if d < 64 {
		n := N.Int64()
		a := int64(math.Sqrt(float64(n)))
		if a*a == n {
			return true
		}
		return false
	}

	// Step 1: make a random guess for sqrt
	// with the right order of magnitude
	bytes := make([]byte, d/16)
	rand.Read(bytes)
	x := new(big.Int).SetBytes(bytes)
	y := new(big.Int)

	// Step 2: run newtons method until it
	// stabilized (same value or one off), see wiki article
	// http://en.wikipedia.org/wiki/Integer_square_root
	// convergence is quadratic so shouldn't take long
	// if it doesn't converge it should alternate between +-1
	// so return false in that case
	for i := 0; i < d; i++ {
		// Set y = [(x + [N/x])/2]
		y.Rsh(new(big.Int).Add(x, new(big.Int).Div(N, x)), 1)
		if i > d/2 {
			if new(big.Int).Abs(new(big.Int).Sub(x, y)).Cmp(bigOne) <= 0 { // |x - y| <= 1
				return new(big.Int).Mul(x, x).Cmp(N) == 0
			}
		}
		x.Set(y)
	}
	return false
}
