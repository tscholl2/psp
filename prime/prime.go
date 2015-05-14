package prime

import (
	"crypto/rand"
	"math"
	"math/big"
)

var (
	// all primes < 10 bits and their product
	prodPrimes10, _ = new(big.Int).SetString("613a0497aa700632594668d2175f6874157ab081f7d649a3e936c6608f20575cb03949974ef1fb62db814d5fdf2c0d0e2d0abb2b26e8cc08403e32336e4bf96f1ffa1b71d1f4c342dc3812e17d7035b9e93905bff2c1a6de", 16)
	primes10        = []uint16{
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
		941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021}
	// diffs to next relatively prime number mod 210 = 2*3*5*7
	diffs = []uint8{
		11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 6,
		5, 4, 3, 2, 1, 2, 1, 6, 5, 4, 3, 2, 1, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 6, 5,
		4, 3, 2, 1, 6, 5, 4, 3, 2, 1, 2, 1, 6, 5, 4, 3, 2, 1, 4, 3, 2, 1, 2, 1, 6,
		5, 4, 3, 2, 1, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1, 4, 3,
		2, 1, 2, 1, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1, 6, 5, 4,
		3, 2, 1, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1,
		2, 1, 6, 5, 4, 3, 2, 1, 6, 5, 4, 3, 2, 1, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 6,
		5, 4, 3, 2, 1, 2, 1, 6, 5, 4, 3, 2, 1, 4, 3, 2, 1, 2, 1, 4, 3, 2, 1, 2, 1,
		10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 2}
	diffsInt []*big.Int
	one      = big.NewInt(1)
	two      = big.NewInt(2)
)

// precomputations
func init() {
	// calculate the diff table for coprimes
	diffsInt = make([]*big.Int, len(diffs))
	for i, d := range diffs {
		diffsInt[i] = big.NewInt(int64(d))
	}
}

// NextPrime returns a number, p, with p >= n
// and high probability that p is the next prime
// occuring after n
func NextPrime(N *big.Int) (p *big.Int) {
	m := len(diffsInt)
	i := int(new(big.Int).Mod(N, big.NewInt(int64(m))).Int64())
	p = new(big.Int).Set(N)
	for {
		if BPSW(p) {
			return
		}
		p.Add(p, diffsInt[i])
		i = (i + int(diffs[i])) % m
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

	//Step 0: parse input
	if N.Sign() <= 0 {
		panic("BPSW is for positive integers only")
	}

	// Step 1: check  all small primes
	// returns 1 if prime, 0 if composite, -1 else
	switch SmallPrimeTest(N) {
	case 1:
		return true
	case 0:
		return false
	}

	// Step 2: Miller-Rabin test
	// returns false if composite
	if !StrongMillerRabin(N, 2) {
		return false
	}

	// Step 3: Lucas-Selfridge test
	// returns false if composite
	if !StrongLucasSelfridgeTest(N) {
		return false
	}

	return true
}

// SmallPrimeTest returns
//  0 if N is composite
//  1 if N is prime
// -1 if undetermined
func SmallPrimeTest(N *big.Int) int {
	if N.Sign() < 0 {
		panic("SmallPrimeTest for non-negative integers only")
	}

	d := new(big.Int)
	if d.GCD(nil, nil, N, prodPrimes10).Cmp(one) == 1 {
		// if d | N and d > 1
		if N.BitLen() < 11 {
			// N may be one of the primes in our list
			n := uint16(N.Int64())
			for _, p := range primes10 {
				if n == p {
					return 1
				}
			}
		}
		return 0
	}

	return -1
}

// StrongMillerRabin returns true if N is a MR
// psuedoprime in base a, i.e., it returns
// false if a is a witness for compositeness
// of N or N os a strong pseudoprime base a
// use .ProbablyPrime if you want to do a lot
// of random tests, this is for one specific
// base value.
func StrongMillerRabin(N *big.Int, a int64) bool {
	// Step 0: parse input
	if N.Sign() < 0 || N.Bit(0) == 0 || a < 2 {
		panic("MR is for positive odd integers with a >= 2")
	}
	A := big.NewInt(a)
	if new(big.Int).GCD(nil, nil, N, A).Cmp(one) != 0 {
		return false
	}

	// Step 1: find d,s, so that n - 1 = d*2^s
	// with d odd
	d := new(big.Int).Sub(N, one)
	s := trailingZeroBits(d)
	d.Rsh(d, s)

	// Step 2: compute powers a^d
	// and then a^(d*2^r) for 0<r<s
	var nm1, Ad big.Int
	Ad.Exp(A, d, N)
	nm1.Sub(N, one)
	if Ad.Cmp(one) == 0 || Ad.Cmp(&nm1) == 0 {
		return true
	}
	for r := uint(1); r < s; r++ {
		Ad.Exp(&Ad, two, N)
		if Ad.Cmp(&nm1) == 0 {
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
	if N.Sign() < 0 || N.Bit(0) == 0 {
		panic("LS is for positive odd integers, check these yourself")
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
		d := new(big.Int).Add(new(big.Int).Abs(D), two)
		if D.Sign() > 0 {
			d.Neg(d)
		}
		D.Set(d)
	}
	// Set some variables
	P := big.NewInt(1) // Selfridge's choice, also set on wiki package
	// http://en.wikipedia.org/wiki/Lucas_pseudoprime#Implementing_a_Lucas_probable_prime_test
	Q := new(big.Int).Mod(new(big.Int).Div(new(big.Int).Sub(one, D), big.NewInt(4)), N)
	//check for some common factors
	if new(big.Int).GCD(nil, nil, N, Q).Cmp(one) != 0 {
		return false
	}

	//fmt.Printf("D = %d\nP = %d\nQ = %d\n", D, P, Q)
	//fmt.Println("Step 3: factor out 2's (d,s)")

	// Step 3: Find d so N+1 = 2^s*d with d odd
	d := new(big.Int).Add(N, one)
	s := trailingZeroBits(d)
	d.Rsh(d, s)

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
	//div2 := new(big.Int).ModInverse(two, N)

	// divides and sets x to be x/2 mod N
	divideBy2ModN := func(x *big.Int) *big.Int {
		if x.Bit(0) != 0 {
			x.Add(x, N)
		}
		return x.Rsh(x, 1)
	}

	Uk := big.NewInt(0)         // U_0 = 0
	Vk := new(big.Int).Set(two) // V_0 = 2
	Qk := new(big.Int).Set(one) // Q^0 = 1
	// follow repeated squaring algorithm
	for i := d.BitLen() - 1; i > -1; i-- {
		//double everything
		Uk.Mod(new(big.Int).Mul(Uk, Vk), N) // now U_{2k}
		Vk.Mod(new(big.Int).Sub(new(big.Int).Mul(Vk, Vk), new(big.Int).Mul(two, Qk)), N)
		Qk.Mod(new(big.Int).Mul(Qk, Qk), N) // now Q^{2k}
		// check small bit
		if d.Bit(i) == 1 {
			// increment by 1
			Qk.Mod(new(big.Int).Mul(Qk, Q), N)
			PxUk := new(big.Int).Mod(new(big.Int).Mul(P, Uk), N)
			DxUk := new(big.Int).Mod(new(big.Int).Mul(D, Uk), N)
			PxVk := new(big.Int).Mod(new(big.Int).Mul(P, Vk), N)
			Uk.Mod(divideBy2ModN(new(big.Int).Add(PxUk, Vk)), N)
			Vk.Mod(divideBy2ModN(new(big.Int).Add(DxUk, PxVk)), N)
		}
	}

	//fmt.Printf("U_d = %d\nV_d = %d\nQ^d = %d\n", Uk, Vk, Qk)

	// U_k, V_k, Q^k are now all with k=d
	if Uk.Sign() == 0 {
		// if U_d = 0
		return true
	}
	// Now we look at powers V_{{2^r}d} for r = 0..s-1
	var r uint
	for r = 0; r < s; r++ {
		if Vk.Sign() == 0 {
			// if V_{2^rd} = 0
			return true
		}
		Vk.Mod(new(big.Int).Sub(new(big.Int).Mul(Vk, Vk), new(big.Int).Mul(two, Qk)), N)
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
	if D.Sign() <= 0 || D.Bit(0) == 0 {
		// we will assume D is positive
		// wolfram is ok with negative denominator
		// im not sure what is standard though
		panic("JacobiSymbol defined for positive odd denominator only")
	}
	var n, d, tmp big.Int
	n.Set(N)
	d.Set(D)
	j := 1

	for {
		// Step 1: Reduce the numerator mod the denominator
		n.Mod(&n, &d)
		if n.Sign() == 0 {
			// if n,d not relatively prime
			return 0
		}

		//fmt.Printf("step 0, \nn = %d\nd = %d\nj = %d\n", &n, &d, j)

		if len(n.Bits()) >= len(d.Bits())-1 {
			// n > d/2 so swap n with d-n
			// and multiply j by JacobiSymbol(-1 / d)
			n.Sub(&d, &n)
			if d.Bits()[0]&3 == 3 {
				// if d = 3 mod 4
				j = -1 * j
			}
		}

		//fmt.Printf("step 1, \nn = %d\nd = %d\nj = %d\n", &n, &d, j)

		// Step 2: extract factors of 2
		s := trailingZeroBits(&n)
		n.Rsh(&n, s)
		if s&1 == 1 {
			switch d.Bits()[0] & 7 {
			case 3, 5: // d = 3,5 mod 8
				j = -1 * j
			}
		}

		//fmt.Printf("step 2, \nn = %d\nd = %d\nj = %d\n", &n, &d, j)

		// Step 3: check numerator
		if len(n.Bits()) == 1 && n.Bits()[0] == 1 {
			// if n = 1 were done
			return j
		}

		// Step 4: flip and go back to step 1
		if n.Bits()[0]&3 != 1 { // n = 3 mod 4
			if d.Bits()[0]&3 != 1 { // d = 3 mod 4
				j = -1 * j
			}
		}
		tmp.Set(&n)
		n.Set(&d)
		d.Set(&tmp)

		//fmt.Printf("step 4, \nn = %d\nd = %d\nj = %d\n", &n, &d, j)

	}
}

func trailingZeroBits(x *big.Int) (i uint) { //TODO fix, use lookup table for words
	if x.Sign() < 0 {
		panic("unknown bits of negative")
	}
	if x.Bit(0) == 1 {
		return 0
	}
	for i = 1; i < uint(x.BitLen()) && x.Bit(int(i)) != 1; i++ {
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
			if new(big.Int).Abs(new(big.Int).Sub(x, y)).Cmp(one) <= 0 { // |x - y| <= 1
				return new(big.Int).Mul(x, x).Cmp(N) == 0
			}
		}
		x.Set(y)
	}
	return false
}
