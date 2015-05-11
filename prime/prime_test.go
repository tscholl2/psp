package prime

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func randBig(bits int) *big.Int {
	bytes := make([]byte, bits/8)
	rand.Read(bytes)
	return new(big.Int).SetBytes(bytes)
}

func check(t *testing.T, expected interface{}, got interface{}) {
	if got != expected {
		t.Error("Expected ", expected, ", got ", got)
	}
}

func checkBigNumbers(t *testing.T, expected *big.Int, got *big.Int) {
	if got.Cmp(expected) != 0 {
		t.Error("Expected ", expected, ", got ", got)
	}
}

func TestNextPrime(t *testing.T) {
	var n *big.Int
	var p *big.Int
	// small checks
	n = big.NewInt(17)
	check(t, 17, int(NextPrime(n).Int64()))
	n = big.NewInt(170)
	check(t, 173, int(NextPrime(n).Int64()))
	n = big.NewInt(1700)
	check(t, 1709, int(NextPrime(n).Int64()))
	n = big.NewInt(17000)
	check(t, 17011, int(NextPrime(n).Int64()))
	n = big.NewInt(170000)
	check(t, 170003, int(NextPrime(n).Int64()))
	n = big.NewInt(1700000)
	check(t, 1700021, int(NextPrime(n).Int64()))
	n, _ = new(big.Int).SetString("632875643785", 10)
	p, _ = new(big.Int).SetString("632875643789", 10)
	checkBigNumbers(t, p, NextPrime(n))
	// big checks
	n, _ = new(big.Int).SetString("563478564785638746587634875", 10)
	p, _ = new(big.Int).SetString("563478564785638746587634881", 10)
	checkBigNumbers(t, p, NextPrime(n))
}

var benchmarkNumber = randBig(1024)

func BenchmarkNextPrime(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NextPrime(benchmarkNumber)
	}
}
