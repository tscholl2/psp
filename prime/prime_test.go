package prime

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// Tests

func TestIsSquare(t *testing.T) {
	cases := []struct {
		in   *big.Int
		want bool
	}{
		{big.NewInt(-1436278), false},
		{big.NewInt(0), true},
		{big.NewInt(1), true},
		{big.NewInt(15), false},
		{big.NewInt(16), true},
		{big.NewInt(13627856 * 13627856), true},
		{big.NewInt(13627856), false},
		{new(big.Int).SetBytes([]byte{0x54, 0xD0, 0xDC, 0x48, 0xD2, 0x1A, 0x26, 0x83, 0x5F, 0x51}), true},
	}
	for _, c := range cases {
		got := IsSquare(c.in)
		if got != c.want {
			t.Errorf("Case: %x\nExpected: %t\nGot: %t", c.in, c.want, got)
		}
	}
}

func TestNextPrime(t *testing.T) {
	cases := []struct {
		in, want *big.Int
	}{
		{big.NewInt(17), big.NewInt(17)},
		{big.NewInt(170), big.NewInt(173)},
		{big.NewInt(1700), big.NewInt(1709)},
		{big.NewInt(17000), big.NewInt(17011)},
		{big.NewInt(170000), big.NewInt(170003)},
		{big.NewInt(1700000), big.NewInt(1700021)},
		{new(big.Int).SetBytes([]byte{0x93, 0x5a, 0x53, 0xf3, 0x89}),
			new(big.Int).SetBytes([]byte{0x93, 0x5a, 0x53, 0xf3, 0x8d})},
		{new(big.Int).SetBytes([]byte{0x1, 0xd2, 0x19, 0x3a, 0x34, 0x58, 0xd0, 0x22, 0x96, 0x33, 0x9c, 0xbb}),
			new(big.Int).SetBytes([]byte{0x1, 0xd2, 0x19, 0x3a, 0x34, 0x58, 0xd0, 0x22, 0x96, 0x33, 0x9c, 0xc1})},
	}
	for _, c := range cases {
		got := NextPrime(c.in)
		if got.Cmp(c.want) != 0 {
			t.Errorf("Case: %x\nExpected: %x\nGot: %x", c.in, c.want, got)
		}
	}
}

func TestJacobiSymbol(t *testing.T) {
	cases := []struct {
		N, D *big.Int
		want int
	}{
		{big.NewInt(15), big.NewInt(45), 0},
		{big.NewInt(19), big.NewInt(45), 1},
		{big.NewInt(8), big.NewInt(21), -1},
		{big.NewInt(5), big.NewInt(21), 1},
		{big.NewInt(1001), big.NewInt(9907), -1},
	}
	for _, c := range cases {
		got := JacobiSymbol(c.N, c.D)
		if got != c.want {
			t.Errorf("Case: ( %d / %d )\nExpected: %x\nGot: %x", c.N, c.D, c.want, got)
		}
	}
}

// Benchmarks

func randBig(bits int) *big.Int {
	bytes := make([]byte, bits/8)
	rand.Read(bytes)
	return new(big.Int).SetBytes(bytes)
}

var benchmarkNumber, _ = new(big.Int).SetString("3ba9a88eb20cfdfe4a380607f5025cdcd0f0bbb73b6f8d45bb0d7bdcd7d485b513d4f8c3d0d572f47ea6f32b4d19978c1a578f919c126e997548b8d0acc64284287a3a321e292e1be9614bf21254011a25df84b77b7411d41e65fd50298fc4660651580b5bd3f38377e2a6260021694cb4096873762f45ba41562ed1cddac60f", 16)
var benchmarkSquare, _ = new(big.Int).SetString("79045c904c4628af5f2d21f726b8bebc1c61f0fceb4f2292bc70ce61adf1646ffcbfdd003703b5da7dc1c39bccf5f71a4c6ad61b6812d70b587aeaf4c03ecd612ba0ad6ac17f7b572e72ba3bc46fbe75d8fc914c76fdead83ef26d62da422e2dd67e098ab7505ebe134feafd8fc9e59662a627a48329864454624f387f7e3e84", 16)
var benchmarkPrime, _ = new(big.Int).SetString("3ba9a88eb20cfdfe4a380607f5025cdcd0f0bbb73b6f8d45bb0d7bdcd7d485b513d4f8c3d0d572f47ea6f32b4d19978c1a578f919c126e997548b8d0acc64284287a3a321e292e1be9614bf21254011a25df84b77b7411d41e65fd50298fc4660651580b5bd3f38377e2a6260021694cb4096873762f45ba41562ed1cddaca67", 16)

func BenchmarkNextPrime(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NextPrime(benchmarkNumber)
	}
}

func BenchmarkIsSquare(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsSquare(benchmarkSquare)
	}
}

func BenchmarkBPSW(b *testing.B) {
	for i := 0; i < b.N; i++ {
		BPSW(benchmarkPrime)
	}
}
