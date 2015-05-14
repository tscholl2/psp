package prime

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// Tests

func TestTrailingZeroBits(t *testing.T) {
	cases := []struct {
		in   *big.Int
		want uint
	}{
		{big.NewInt(0), 1},
		{big.NewInt(1), 0},
		{big.NewInt(2), 1},
		{big.NewInt(3), 0},
		{big.NewInt(4), 2},
		{big.NewInt(6), 1},
		{big.NewInt(8), 3},
		{big.NewInt(15), 0},
		{big.NewInt(16), 4},
		{big.NewInt(32), 5},
		{big.NewInt(3571), 0},
	}
	for _, c := range cases {
		got := trailingZeroBits(c.in)
		if got != c.want {
			t.Errorf("Case: %d\nExpected: %d\nGot: %d", c.in, c.want, got)
		}
	}
}

func TestIsSquare(t *testing.T) {
	n1true, _ := new(big.Int).SetString("240e16068a04dea390a1f96b3f05a1", 16)
	n1false, _ := new(big.Int).SetString("240e16068a04dea390a1f96b3f05a2", 16)
	n2true, _ := new(big.Int).SetString("fa8bf08953f8b2c1f941de3fd45b952967a055ff7826e4a436b660db443b024eaeed6fdf0640", 16)
	n2false, _ := new(big.Int).SetString("fa8bf08953f8b2c1f941de3fd45b952967a055ff7826e4a436b660db443b024eaeed6fdf0641", 16)
	n3false, _ := new(big.Int).SetString("1e04ded686bffea61355f4c9c76f1e66fba27b9fa8b00f3c5884d3eff369677ad5817d783aa58db408de1310e55cd5e72a8176340", 16)
	n3true, _ := new(big.Int).SetString("1e04ded686bffea61355f4c9c76f1e66fba27b9fa8b00f3c5884d3eff369677ad5817d783aa58db408de1310e55cd5e72a8176341", 16)
	n3false2, _ := new(big.Int).SetString("1e04ded686bffea61355f4c9c76f1e66fba27b9fa8b00f3c5884d3eff369677ad5817d783aa58db408de1310e55cd5e72a8176342", 16)
	n4true, _ := new(big.Int).SetString("7afee5555433fa458dc6e8e62f1cc4533b3488893e4067830385d9b27fbf724f0ca5e4e94a1c46afb09138c1965d8aa8938bebd89ae3b4f13aecd85839f3b5db1c7b9692bc0ef2595cf8640", 16)
	n4false, _ := new(big.Int).SetString("7afee5555433fa458dc6e8e62f1cc4533b3488893e4067830385d9b27fbf724f0ca5e4e94a1c46afb09138c1965d8aa8938bebd89ae3b4f13aecd85839f3b5db1c7b9692bc0ef2595cf8641", 16)

	cases := []struct {
		in   *big.Int
		want bool
	}{
		{big.NewInt(-1436278), false},
		{big.NewInt(0), true},
		{big.NewInt(1), true},
		{big.NewInt(15), false},
		{big.NewInt(16), true},
		{big.NewInt(3571), false},
		{big.NewInt(13627856 * 13627856), true},
		{big.NewInt(13627856), false},
		{n1true, true},
		{n2true, true},
		{n3true, true},
		{n4true, true},
		{n1false, false},
		{n2false, false},
		{n3false, false},
		{n3false2, false},
		{n4false, false},
	}
	for _, c := range cases {
		got := IsSquare(c.in)
		if got != c.want {
			t.Errorf("Case: %x\nExpected: %t\nGot: %t", c.in, c.want, got)
		}
	}
}

func TestStrongLucasSelfridgeTest(t *testing.T) {
	n, _ := new(big.Int).SetString("319889369713946602502766595032347", 10)
	//http://www.sciencedirect.com/science/article/pii/S0747717185710425
	cases := []struct {
		in   *big.Int
		want bool
	}{

		{big.NewInt(3 * 5 * 11 * 13 * 17), false}, // smooth number
		{big.NewInt(3), true},                     // some small primes
		{big.NewInt(5), true},
		{big.NewInt(11), true},
		{big.NewInt(797), true},
		{big.NewInt(3571 * 3571), false}, // perfect square
		{big.NewInt(3571), true},         // large prime
		{big.NewInt(5459), true},         // NOT prime! a strong Lucas psuedoprime
		{n, true},                        //also a strong lsps!, BPSW says composite though
	}
	for _, c := range cases {
		got := StrongLucasSelfridgeTest(c.in)
		if got != c.want {
			t.Errorf("Case: %d\nExpected: %t\nGot: %t", c.in, c.want, got)
		}
	}
}

func TestMillerRabin(t *testing.T) {
	cases := []struct {
		inN  *big.Int
		inA  int64
		want bool
	}{
		{big.NewInt(221), 174, true},
		{big.NewInt(221), 137, false},
		{big.NewInt(7), 2, true},
		{big.NewInt(11), 2, true},
		{big.NewInt(13), 2, true},
		{big.NewInt(1709), 2, true},
		{big.NewInt(2005), 2, false},
		{big.NewInt(2047), 2, true}, // NOT prime!
		{big.NewInt(173), 6, true},
		{big.NewInt(175), 5, false}, // not relatively prime
		{big.NewInt(217), 6, true},  // NOT prime!
	}
	for _, c := range cases {
		got := StrongMillerRabin(c.inN, c.inA)
		if got != c.want {
			t.Errorf("Case: ( %d , %d )\nExpected: %t\nGot: %t", c.inN, c.inA, c.want, got)
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
		//{big.NewInt(15), big.NewInt(45), 0},
		{big.NewInt(19), big.NewInt(45), 1},
		/*{big.NewInt(8), big.NewInt(21), -1},
		{big.NewInt(5), big.NewInt(21), 1},
		{big.NewInt(1001), big.NewInt(9907), -1},
		{big.NewInt(-7), big.NewInt(5459), -1},
		{big.NewInt(7), big.NewInt(5459), 1},
		{big.NewInt(21), big.NewInt(3333), 0},*/
	}
	for _, c := range cases {
		got := JacobiSymbol(c.N, c.D)
		if got != c.want {
			t.Errorf("Case: ( %d / %d )\nExpected: %x\nGot: %x", c.N, c.D, c.want, got)
		}
		//got = Jacobi(c.N, c.D)
		//if got != c.want {
		//	t.Errorf("Case: ( %d / %d )\nExpected: %x\nGot: %x", c.N, c.D, c.want, got)
		//}
	}
}

// Benchmarks

func randBig(bits int) *big.Int {
	bytes := make([]byte, bits/8)
	rand.Read(bytes)
	return new(big.Int).SetBytes(bytes)
}

var benchmarkNumber, _ = new(big.Int).SetString("3ba9a88eb20cfdfe4a380607f5025cdcd0f0bbb73b6f8d45bb0d7bdcd7d485b513d4f8c3d0d572f47ea6f32b4d19978c1a578f919c126e997548b8d0acc64284287a3a321e292e1be9614bf21254011a25df84b77b7411d41e65fd50298fc4660651580b5bd3f38377e2a6260021694cb4096873762f45ba41562ed1cddac60f", 16)
var benchmarkOdd, _ = new(big.Int).SetString("3ba9a88eb20cfdfe4a380607f5025cdcd0f0bbb73b6f8d45bb0d7bdcd7d485b513d4f8c3d0d572f47ea6f32b4d19978c1a578f919c126e997548b8d0acc64284287a3a321e292e1be9614bf21254011a25df84b77b7411d41e65fd50298fc4660651580b5bd3f38377e2a6260021694cb4096873762f45ba41562ed1cddaca69", 16)
var benchmarkEven, _ = new(big.Int).SetString("3ba9a88eb20cfdfe4a380607f5025cdcd0f0bbb73b6f8d45bb0d7bdcd7d485b513d4f8c3d0d572f47ea6f32b4d19978c1a578f919c126e997548b8d0acc64284287a3a321e292e1be9614bf21254011a25df84b77b7411d41e65fd50298fc4660651580b5bd3f38377e2a6260021694cb4096873762f45ba41562ed1cddaca67", 16)
var benchmarkSquare, _ = new(big.Int).SetString("79045c904c4628af5f2d21f726b8bebc1c61f0fceb4f2292bc70ce61adf1646ffcbfdd003703b5da7dc1c39bccf5f71a4c6ad61b6812d70b587aeaf4c03ecd612ba0ad6ac17f7b572e72ba3bc46fbe75d8fc914c76fdead83ef26d62da422e2dd67e098ab7505ebe134feafd8fc9e59662a627a48329864454624f387f7e3e84", 16)
var benchmarkPrime, _ = new(big.Int).SetString("3ba9a88eb20cfdfe4a380607f5025cdcd0f0bbb73b6f8d45bb0d7bdcd7d485b513d4f8c3d0d572f47ea6f32b4d19978c1a578f919c126e997548b8d0acc64284287a3a321e292e1be9614bf21254011a25df84b77b7411d41e65fd50298fc4660651580b5bd3f38377e2a6260021694cb4096873762f45ba41562ed1cddaca67", 16)

// keep compiler from optimizing tests
var bigResult *big.Int
var boolResult bool
var intResult int

func BenchmarkStrongMillerRabin(b *testing.B) {
	var r bool
	for i := 0; i < b.N; i++ {
		r = StrongMillerRabin(benchmarkPrime, 2)
	}
	boolResult = r
}

func BenchmarkStrongLucasSelfridgeTest(b *testing.B) {
	var r bool
	for i := 0; i < b.N; i++ {
		r = StrongLucasSelfridgeTest(benchmarkPrime)
	}
	boolResult = r
}

func BenchmarkNextPrime(b *testing.B) {
	var r *big.Int
	for i := 0; i < b.N; i++ {
		r = NextPrime(benchmarkNumber)
	}
	bigResult = r
}

func BenchmarkIsSquare(b *testing.B) {
	var r bool
	for i := 0; i < b.N; i++ {
		r = IsSquare(benchmarkSquare)
	}
	boolResult = r
}

func BenchmarkSmallPrimeTest(b *testing.B) {
	var r int
	for i := 0; i < b.N; i++ {
		r = SmallPrimeTest(benchmarkPrime)
	}
	intResult = r
}

func BenchmarkBPSW(b *testing.B) {
	var r bool
	for i := 0; i < b.N; i++ {
		r = BPSW(benchmarkPrime)
	}
	boolResult = r
}

func BenchmarkJacobiSymbol(b *testing.B) {
	var r int
	for i := 0; i < b.N; i++ {
		r = JacobiSymbol(benchmarkPrime, benchmarkOdd)
	}
	intResult = r
}

func BenchmarkProbablyPrime(b *testing.B) {
	var r bool
	for i := 0; i < b.N; i++ {
		r = benchmarkPrime.ProbablyPrime(10)
	}
	boolResult = r
}
