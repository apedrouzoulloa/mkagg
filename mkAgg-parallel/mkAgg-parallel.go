// Copyright 2024 Alberto Pedrouzo Ulloa
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/bignum"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// ----------------------------------------------------------------------------------------------//
// For more details about multi-key secure aggregation with HE see the preliminary work "Practical Multi-Key Homomorphic Encryption for More Flexible and Efficient Secure Federated Average Aggregation"
// (<https://ieeexplore.ieee.org/document/10224979> or <https://eprint.iacr.org/2022/1674>)
// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// mkAgg.go can be run in two different ways:
//
// (1) o To run with specific parameters in command line execute for example:
//			go run ./mkAgg.go -commandline -numparties 10 -numgoroutinescloud 1 -numgoroutinesparties 1 -numctxperparty 2 -qlevel 2 -pprimelevel 1 -plevel 0 -logN 11 -bitlevelsize 30
// 	   o To run with default parameters from command line:
//			go run ./mkAgg.go -commandline
//
// (2) o To run a batch of multiple aggregations with several parameters stored in the variable "benchParameters" execute:
//			go run ./mkAgg.go
//
// Comments: The code of this script was started by relying on the Examples folder available in Lattigo "https://github.com/tuneinsight/lattigo"
// ----------------------------------------------------------------------------------------------//

// Definition of command line variables
var flagCommandLine = flag.Bool("commandline", false, "run the example with the command-line parameters.")
var flagNumParties = flag.Int("numparties", 20, "number of input parties.")
var flagNumGoRoutinesCloud = flag.Int("numgoroutinescloud", 12, "number of Go routines used by aggregator.")
var flagNumGoRoutinesParties = flag.Int("numgoroutinesparties", 12, "number of Go routines used by input parties.")
var flagNumCtxPerParty = flag.Int("numctxperparty", 10, "size of the model updates to aggregate.")
var flagQLevel = flag.Int("qlevel", 2, "level of Q.")
var flagPprimeLevel = flag.Int("pprimelevel", 1, "level of Pprime.")
var flagPLevel = flag.Int("plevel", 0, "level of P.")
var flaglogN = flag.Int("logN", 10, "logarithm of lattice dimension.")
var flagBitLevelSize = flag.Int("bitlevelsize", 16, "size in bits of each level.")
var flagPreComputeA = flag.Bool("precomputea", false, "'a' polynomials components are precomputed before the encryption phase.")

// parameters: general onfiguration settings for private aggregation
type parameters struct {

	// Protocol parameters
	NumParties           int
	n                    int // n = Number of ciphertexts per party to aggregate in each round (n*N corresponds to the "Size" of the model to aggregate)
	NumGoRoutinesCloud   int
	NumGoRoutinesParties int
	PreComputeA          bool

	// Cryptographic parameters
	logN        int    // quotient polynomial Ring degree
	logQ        [2]int // logQ[0] = #Primes, logQ[1] = Primes bit-size
	pprimelevel int    // pprimelevel = plevel + 1
	plevel      int    // Maximum level for the modulus "p" (level 0 is the lowest available level)
}

// benchParameters: configuration of multiple aggregations to be tested. Used with go run ./mkAgg.go
var benchParameters = []parameters{

	// Parameter set 1 in report
	{NumParties: 16, n: 128, PreComputeA: false, NumGoRoutinesCloud: 1, NumGoRoutinesParties: 1, logN: 13, logQ: [2]int{9, 22}, pprimelevel: 1, plevel: 0},
	//{NumParties: 16, n: 128, PreComputeA: false, NumGoRoutinesCloud: 4, NumGoRoutinesParties: 1, logN: 13, logQ: [2]int{9, 22}, pprimelevel: 1, plevel: 0},
	//{NumParties: 16, n: 128, PreComputeA: false, NumGoRoutinesCloud: 12, NumGoRoutinesParties: 1, logN: 13, logQ: [2]int{9, 22}, pprimelevel: 1, plevel: 0},

	// Parameter set 2 in report
	//{NumParties: 16, n: 128, PreComputeA: false, NumGoRoutinesCloud: 1, NumGoRoutinesParties: 1, logN: 13, logQ: [2]int{7, 30}, pprimelevel: 1, plevel: 0},
	//{NumParties: 16, n: 128, PreComputeA: false, NumGoRoutinesCloud: 4, NumGoRoutinesParties: 1, logN: 13, logQ: [2]int{7, 30}, pprimelevel: 1, plevel: 0},
	//{NumParties: 16, n: 128, PreComputeA: false, NumGoRoutinesCloud: 12, NumGoRoutinesParties: 1, logN: 13, logQ: [2]int{7, 30}, pprimelevel: 1, plevel: 0},

	// Parameter set 3 in report
	//{NumParties: 16, n: 64, PreComputeA: false, NumGoRoutinesCloud: 1, NumGoRoutinesParties: 1, logN: 14, logQ: [2]int{8, 30}, pprimelevel: 2, plevel: 1},
	//{NumParties: 16, n: 64, PreComputeA: false, NumGoRoutinesCloud: 4, NumGoRoutinesParties: 4, logN: 14, logQ: [2]int{8, 30}, pprimelevel: 2, plevel: 1},
	//{NumParties: 16, n: 64, PreComputeA: false, NumGoRoutinesCloud: 12, NumGoRoutinesParties: 4, logN: 14, logQ: [2]int{8, 30}, pprimelevel: 2, plevel: 1},

}

// To check no errors happened during execution of a function
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// To measure time execution of operations done by one party
func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

// To measure time execution of the same operations which are simultaneously done in "parallel" by N parties
func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

// party: defines the inputs and private information of party P_i
type party struct {
	sk ring.Poly // sk_i (individual secret key of party P_i)
	r  ring.Poly // r_i (individual secret share of party P_i)

	input []ring.Poly

	PaddedNumModelParameters int // Size of the vector of model updates with zero padding (till the next multiple of params.N() => PaddedNumModelParameters = k*params.N(), where k is the smallest integer satisfying k*params.N() >= real number of NumModelParameters)
}

// multTask: structure used for the parallelization with Go routines in aggregation/decryption phases of type (1)
type multTask struct {
	wg          *sync.WaitGroup
	op1         []ring.Poly //changed from pointer to proper variable
	op2         []ring.Poly //changed from pointer to proper variable
	res         []ring.Poly //changed from pointer to proper variable
	elapsedTask time.Duration
}

// multTaskEnc: structure used for the parallelization with Go routines in encryption phase
type multTaskEnc struct {
	wg             *sync.WaitGroup
	op1            ring.Poly //changed from pointer to proper variable
	op2            ring.Poly //changed from pointer to proper variable
	op3            ring.Poly //changed from pointer to proper variable
	op4            ring.Poly //changed from pointer to proper variable
	res1           ring.Poly //changed from pointer to proper variable
	res2           ring.Poly //changed from pointer to proper variable
	elapsedTaskEnc time.Duration
}

// multTaskRounding: structure used for the parallelization with Go routines in aggregation phase of type (2)
type multTaskRounding struct {
	wg                  *sync.WaitGroup
	op                  ring.Poly //changed from pointer to proper variable
	elapsedTaskRounding time.Duration
}

// multTaskRoundingDec: structure used for the parallelization with Go routines in decryption phase of type (2)
type multTaskRoundingDec struct {
	wg                     *sync.WaitGroup
	op1                    ring.Poly //changed from pointer to proper variable
	op2                    ring.Poly //changed from pointer to proper variable
	res                    ring.Poly //changed from pointer to proper variable
	elapsedTaskRoundingDec time.Duration
}

// Definition of variables used to measure runtime for specific steps of the aggregation protocol
var elapsedSetupCloud time.Duration // elapsedSetupCloud = 0 (no setup required for the Aggregator)
var elapsedSetupParty time.Duration
var elapsedSetupGaussianParty time.Duration
var elapsedPreprocessingEncryptParty time.Duration
var elapsedPreprocessingUniformSamplersParty time.Duration
var elapsedEncryptParty time.Duration
var elapsedEncryptPartyCPU time.Duration
var elapsedEncryptPartyWall time.Duration
var elapsedEncryptCloud time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalCloudWall time.Duration
var elapsedEvalParty time.Duration
var elapsedDecCloud time.Duration
var elapsedDecParty time.Duration
var elapsedDecCloudCPU time.Duration
var elapsedDecCloudWall time.Duration

// AggRings: structure used to store variables related to the used quotient rings in the aggegation protocol
type AggRings struct {
	ringQ      *ring.Ring // Z_{Q}/(X^N+1)
	QDivP      *big.Int   // Q/P
	QDivPprime *big.Int   // Q/P'
	PprimeDivP *big.Int   // P'/P
}

// newAggRings: defines and initializes an AggRings variable
func newAggRings(params parameters) *AggRings {

	// Check that plevel is strictly less than pprimelevel
	if params.plevel >= params.pprimelevel {
		panic("plevel must be strictly smaller than pprimelevel")
	}

	var err error

	N := 1 << params.logN // N is set as 2^logN

	rings := new(AggRings)

	// Create a generator for primes (of the specified bit size) compatible with negacyclic NTT for the given N
	g := ring.NewNTTFriendlyPrimesGenerator(uint64(params.logQ[1]), uint64(2*N))

	// Generate k = params.logQ[0] NTT-friendly primes, each approximately close to 2^logQ[1]
	primes, err := g.NextAlternatingPrimes(params.logQ[0])
	check(err)

	// Create the polynomial ring Z[x]_Q / (x^N + 1) with a modulus over an RNS with as many primes as in "primes"
	rings.ringQ, err = ring.NewRing(N, primes)
	check(err)

	// Initialize QDivP as 1 and compute QDivP = Q / P as the product of primes from plevel + 1 onward
	rings.QDivP = bignum.NewInt(1)
	for _, qi := range primes[params.plevel+1:] {
		rings.QDivP.Mul(rings.QDivP, bignum.NewInt(qi))
	}

	// Initialize QDivPprime as 1 and compute QDivPprime = Q / P' as the product of primes from pprimelevel + 1 onward
	rings.QDivPprime = bignum.NewInt(1)
	for _, qi := range primes[params.pprimelevel+1:] { // Note: Golang slices do not include the last index
		rings.QDivPprime.Mul(rings.QDivPprime, bignum.NewInt(qi))
	}

	// Initialize PprimeDivP as 1 and compute PprimeDivP = P' / P as the product of primes from plevel + 1 to pprimelevel
	rings.PprimeDivP = bignum.NewInt(1)
	for _, qi := range primes[params.plevel+1 : params.pprimelevel+1] { // Note: Golang slices do not include the last index
		rings.PprimeDivP.Mul(rings.PprimeDivP, bignum.NewInt(qi))
	}

	return rings
}

// lowNormSampler: this structure is used to store the gaussian values in *Big.Int. We indicate the ring base in which we work (mod Q =  limb0*limb1*...)
type lowNormSampler struct {
	baseRing *ring.Ring
	coeffs   []*big.Int
}

// newLowNormSampler: initializes a lowNormSampler structure based on the provided base ring. Given a "baseRing" of type *ring.Ring, it allocates memory for the lowNormSampler structure.
func newLowNormSampler(baseRing *ring.Ring) (lns *lowNormSampler) {
	lns = new(lowNormSampler)
	lns.baseRing = baseRing
	lns.coeffs = make([]*big.Int, baseRing.N())
	return
}

// newPolyLowNorm: generates a uniform random polynomial in Z_{norm}/(X^N + 1). This method is associated with the lowNormSampler structure and transforms random values into the polynomial structure required by the ring.
func (lns *lowNormSampler) newPolyLowNorm(norm *big.Int) (pol ring.Poly) {

	// Initialize an empty polynomial in the base ring
	pol = lns.baseRing.NewPoly()

	// Initialize a pseudorandom number generator (PRNG) for coefficient sampling
	prng, _ := sampling.NewPRNG()

	// Sample each coefficient uniformly in the range [0, norm - 1]
	for i := range lns.coeffs {
		lns.coeffs[i] = bignum.RandInt(prng, norm)
	}

	// Set the coefficients of "pol" using lns.coeffs, formatted according to baseRing's structure
	lns.baseRing.AtLevel(pol.Level()).SetCoefficientsBigint(lns.coeffs, pol) // The AtLevel function adjusts the ring's structure to match the required level for polynomial operations
	return
}

// ----------------------------------------------------------------------------------------------//
// Information extracted from Lattigo library "https://github.com/tuneinsight/lattigo" (it can be used to generate the correlated randomness):
// ----------------------------------------------------------------------------------------------//
// KeyedPRNG is a structure storing the parameters used to securely and deterministically generate shared
// sequences of random bytes among different parties using the hash function blake2b. Backward sequence
// security (given the digest i, compute the digest i-1) is ensured by default, however forward sequence
// security (given the digest i, compute the digest i+1) is only ensured if the KeyedPRNG is keyed.
// ----------------------------------------------------------------------------------------------//

// main function. Example executions:
// (1) From command line parameters: go run ./mkAgg.go -commandline -numparties 10 -numgoroutinescloud 1 -numgoroutinesparties 1 -numctxperparty 2 -qlevel 2 -pprimelevel 1 -plevel 0 -logN 11 -bitlevelsize 30
// (2) From parameters in benchParameters: go run ./mkAgg.go
func main() {

	// ----------------------------------------------------------------------------------------------//
	// For more details about the multi-key secure aggregation rule with HE, see the preliminary work "Practical Multi-Key Homomorphic Encryption for More Flexible and Efficient Secure Federated Average Aggregation"
	// (<https://ieeexplore.ieee.org/document/10224979> or <https://eprint.iacr.org/2022/1674>)
	// ----------------------------------------------------------------------------------------------//
	// $go run main.go -commandline arg1 arg2 arg3 ...
	//  -numparties: number of parties
	//  -numgoroutinescloud: number of Go routines used by the aggregator
	//  -numgoroutinesparties: number of Go routines used by the Data Owners
	//  -numctxperparty: number of ctxs used to encrypt the model updates. Model size = N*numctxperparty
	//  -qlevel: number of limbs for Q
	//  -pprimelevel: number of limbs for P'
	//  -plevel: number of limbs for P
	//  -logN: logarithm of lattice dimension
	//  -bitlevelsize: size in bits of each limb
	//  -precomputea: "a" polynomials are precomputed before running the aggregation protocol
	// ----------------------------------------------------------------------------------------------//

	// ----------------------------------------------------------------------------------------------//
	// Parsing the configuration of parameters for aggregation
	// ----------------------------------------------------------------------------------------------//

	flag.Parse()

	// If "-commandline", we assign command-line flags and/default values.
	paramsSets := benchParameters
	if *flagCommandLine {
		paramsSets = benchParameters[0:1]
		paramsSets[0].logN = *flaglogN
		paramsSets[0].logQ = [2]int{*flagQLevel + 1, *flagBitLevelSize}
		paramsSets[0].pprimelevel = *flagPprimeLevel
		paramsSets[0].plevel = *flagPLevel
		paramsSets[0].n = *flagNumCtxPerParty
		paramsSets[0].NumParties = *flagNumParties
		paramsSets[0].NumGoRoutinesCloud = *flagNumGoRoutinesCloud
		paramsSets[0].NumGoRoutinesParties = *flagNumGoRoutinesParties
		paramsSets[0].PreComputeA = *flagPreComputeA
	}

	// ----------------------------------------------------------------------------------------------//

	// ----------------------------------------------------------------------------------------------//
	// Running several aggregation examples
	// ----------------------------------------------------------------------------------------------//

	for _, param := range paramsSets {

		// ----------------------------------------------------------------------------------------------//
		// Cryptographic parameters and initialization of samplers
		// ----------------------------------------------------------------------------------------------//

		// Initialize cryptographic parameters and structures for aggregation
		priaggrings := newAggRings(param) // Aggregation ring setup
		ringQ := priaggrings.ringQ

		// Extract protocol and cryptographic parameters from the current configuration
		n := param.n                                       // Number of ciphertexts per party to aggregate
		qlevel := ringQ.MaxLevel()                         // Maximum level for the ciphertext ring modulus
		pprimelevel := param.pprimelevel                   // p' modulus level
		plevel := param.plevel                             // p modulus level
		levelsize := param.logQ[1]                         // Bit size of the modulus primes
		NumParties := param.NumParties                     // Number of parties in the protocol
		NumGoRoutinesCloud := param.NumGoRoutinesCloud     // Number of goroutines used in cloud processing
		NumGoRoutinesParties := param.NumGoRoutinesParties // Number of goroutines per party
		PreComputeA := param.PreComputeA                   // Flag for pre-computation optimization

		// Display protocol and cryptographic parameter details
		fmt.Printf("\n-----------------------------------------------------------------------------------------------\n")
		fmt.Printf("Protocol Parameters:\n>>> Nparties=%d Ctxs.Round=%d NGoRoutinesCloud=%d NGoRoutinesParties=%d", NumParties, n, NumGoRoutinesCloud, NumGoRoutinesParties)
		fmt.Printf("\n-----------------------------------------------------------------------------------------------")
		fmt.Printf("\nCryptographic Parameters:\n>>> logN=%d qlevel=%d pprimelevel=%d plevel=%d levelSize=%d bits", param.logN, qlevel, pprimelevel, plevel, levelsize)
		fmt.Printf("\n-----------------------------------------------------------------------------------------------\n")

		// Initialize a pseudorandom number generator for sampling
		prng, err := sampling.NewPRNG()
		check(err)

		// Initialize ternary sampler for ringQ, with P:2.0/3.0 which gives a ternary uniform distribution {-1, 0, 1} -> 1/3, 1/3, 1/3
		ternarySamplerMontgomeryQ, err := ring.NewSampler(prng, ringQ, ring.Ternary{P: 2.0 / 3.0}, true)
		check(err)

		// Initialize Gaussian sampler with a standard deviation of 3.2, upper bound set to approximately 6 * sigma
		gaussianSamplerQ, err := ring.NewSampler(prng, ringQ, ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2}, false) //B_sigma = 6*Sigma
		check(err)
		_ = gaussianSamplerQ // Placeholder to prevent unused variable error

		// Initialize uniform sampler for ringQ for uniformly random coefficients
		uniformSamplerQ, err := ring.NewSampler(prng, ringQ, ring.Uniform{}, false)
		check(err)

		// Initialize low-norm sampler for generating low-norm polynomials in ringQ
		lowNormUniformQ := newLowNormSampler(ringQ)
		// ----------------------------------------------------------------------------------------------//

		// ----------------------------------------------------------------------------------------------//
		// 1. SETUP PHASE
		// ----------------------------------------------------------------------------------------------//

		// Output message indicating the start of the initialization phase for secret key (sk) and random (r) values
		fmt.Printf("\n> Initialization of sk and r for all Parties - (estimated runtimes with no parallelization)\n")
		elapsedSetupParty = time.Duration(0)

		// NTT(MForm(ski)): Generate the secret key (ski) for each party using NTT and MForm transformation
		P := genParties(priaggrings, ternarySamplerMontgomeryQ, NumParties)

		// NTT(MForm(ri)) such that ∑ri = 0: Generate the random share (ri) for each party such that the sum of all shares equals 0
		genSetupShare(priaggrings, uniformSamplerQ, P)

		// Generate an array of "n" polynomials for each party, where each polynomial is uniformly random in Z_P[x]/(1 + x^N)
		fmt.Println("\n> Generation of mi for all Parties. Working with model updates of size:", n*(1<<param.logN), "parameters - (estimated runtimes with no parallelization)")
		aggexparray := genInputs(priaggrings, lowNormUniformQ, n, P, param) // The expected result is the aggregation of all the party models (aggexp = m_0 + m_1 + ... + m_{L-1})

		// Output message indicating the completion of the setup phase for both cloud and party components
		fmt.Printf("\n> Setup done (cloud: %s, party: %s) - (estimated runtimes with no parallelization)\n", elapsedSetupCloud, elapsedSetupParty)

		// ----------------------------------------------------------------------------------------------//

		// ----------------------------------------------------------------------------------------------//
		// 2. ENCRYPTION PHASE
		// ----------------------------------------------------------------------------------------------//

		// encPhase:
		// 	Inputs => "a", "m", "sk", "r"
		// 	Outputs => enc(a, m, "mask"), partialdec(a, sk)

		// Encrypt: a*(si + ri) + e + QDivP*m[i]
		encInput, partialDec := encPhaseParallel(priaggrings, PreComputeA, NumGoRoutinesParties, uniformSamplerQ, n, P, param) // Perform encryption with Goroutines, sharing the prng for uniform sampling (uniformSamplerQ) across parties

		// Output message indicating the completion of the encryption phase for both cloud and party components
		fmt.Printf("\n> Encryption done (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

		// ----------------------------------------------------------------------------------------------//

		// ----------------------------------------------------------------------------------------------//
		// 3. AGGREGATION PHASE
		// ----------------------------------------------------------------------------------------------//

		// Aggregation phase:
		// Inputs => c0, c1, ..., c_{L - 1} (ciphertexts from all parties)
		// Outputs => cagg = c0 + c1 + ... + c_{L - 1} (aggregated ciphertext result)

		encShareAgg := evalPhaseParallel(priaggrings, n, NumGoRoutinesCloud, encInput, param) // Perform aggregation withGoroutines across cloud workers

		// Output message indicating the completion of the aggregation phase for both cloud and party components
		fmt.Printf("\n> Aggregation done (cloud: %s, party: %s)\n", elapsedEvalCloud, elapsedEvalParty)

		// ----------------------------------------------------------------------------------------------//

		// ----------------------------------------------------------------------------------------------//
		// 3. DECRYPTION PHASE
		// ----------------------------------------------------------------------------------------------//

		//decPhase:
		// Inputs => partialdec(a, sk_i) (partial decryption of each party's input), aggoutputenc (aggregated encrypted ciphertext)
		// Outputs => recAggShare = partialdec(a,sk_i) + aggoutputenc (reconstructed aggregated result after decryption)

		recAggShare := decPhaseParallel(priaggrings, NumGoRoutinesCloud, partialDec, encShareAgg, n, param) // Perform decryption and aggregation with Goroutines across cloud workers

		// Output message indicating the completion of the decryption phase for both cloud and party components
		fmt.Printf("\n> Decryption done (cloud: %s, party: %s)\n", elapsedDecCloud, elapsedDecParty)
		// ----------------------------------------------------------------------------------------------//

		// ----------------------------------------------------------------------------------------------//
		// 4. SHOW RUNTIME EXECUTION
		// ----------------------------------------------------------------------------------------------//

		// Display the total execution time for the cloud components (sum of all cloud phases) and the total execution time per party (sum of all phases for each party)
		fmt.Printf("\n> Finished (total cloud: %s, total per party: %s)\n", elapsedSetupCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedDecCloud, elapsedEncryptParty+elapsedEvalParty+elapsedDecParty)

		// ----------------------------------------------------------------------------------------------//

		// ----------------------------------------------------------------------------------------------//
		// 5. CHECK RESULTS
		// ----------------------------------------------------------------------------------------------//

		// Initialize a counter to track the number of errors (discrepancies) between expected and actual results
		nerrors := 0

		// Loop through the aggregated result array and compare each element with the corresponding expected result
		for i := 0; i < n; i++ {
			if !ringQ.AtLevel(plevel).Equal(aggexparray[i], recAggShare[i]) { // Use the Equal function from the ringQ to check if the polynomials are identical at the given level (plevel)
				nerrors++ // Increment error count if the two polynomials do not match
			}
		}

		// Output the total number of errors detected in the aggregation phase
		fmt.Printf("\nErrors Aggregation : %d\n", nerrors)

		// ----------------------------------------------------------------------------------------------//

	}

	// ----------------------------------------------------------------------------------------------//
}

// ----------------------------------------------------------------------------------------------//
// Generates the invidividual secret key "ski" for each Data Owner Party P[i]
// ----------------------------------------------------------------------------------------------//

// genParties initializes each data owner party and generates their individual secret key.
// Inputs:
// - aggring: Aggregation ring structure containing the cryptographic parameters
// - secretkeysampler: Sampler used to generate secret keys
// - NumParties: Total number of data owner parties
// Outputs:
// - Returns an array of *party structures, each containing an initialized secret key for a data owner

func genParties(aggring *AggRings, secretkeysampler ring.Sampler, NumParties int) []*party {

	// Allocate memory for each party's structure and the necessary shares for protocol operations
	P := make([]*party, NumParties)

	// Track the setup time for party initialization
	elapsedSetupParty += runTimedParty(func() {

		// Generate and initialize the secret key for each party
		for i := range P {
			pi := &party{}                     // Create a new party instance
			pi.sk = secretkeysampler.ReadNew() // Generate a new secret key using the provided sampler
			aggring.ringQ.NTT(pi.sk, pi.sk)    // Transform the secret key to the NTT domain for efficient polynomial operations
			P[i] = pi                          // Assign the initialized party to the party array
		}
	}, NumParties)

	return P // Return the array of initialized parties
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Generates the individual share "ri" for each Data Owner Party P[i]
// ----------------------------------------------------------------------------------------------//

// genSetupShare initializes the share "ri" for each party so that the sum of all "ri" values is zero.
// Inputs:
// - aggring: Aggregation ring structure containing the cryptographic parameters
// - uniformsampler: Sampler used to generate uniform random values for each "ri"
// - P: Array of parties, each of which will receive an "ri" share
func genSetupShare(aggring *AggRings, uniformsampler ring.Sampler, P []*party) {

	// Create each party and allocate memory for all shares required by the protocol.
	// The goal is to set up the shares "ri" for each party such that:
	//     NTT(MForm(r_{L-1})) = -(NTT(MForm(r_0)) + NTT(MForm(r_1)) + ... + NTT(MForm(r_{L-2})))
	// This ensures that the sum of all shares is zero, which is essential for the aggregation protocol.

	// Track the setup time for generating shares for all parties
	elapsedSetupParty += runTimedParty(func() {

		// Initialize the last party's "r" to accumulate the negated sum of previous shares
		P[len(P)-1].r = aggring.ringQ.NewPoly()

		// Generate the "ri" shares for each party except the last
		for _, pi := range P[:len(P)-1] {
			pi.r = uniformsampler.ReadNew() // Generate a new uniform random share for each party
			aggring.ringQ.NTT(pi.r, pi.r)   // Convert the share to the NTT domain
			aggring.ringQ.MForm(pi.r, pi.r) // Apply the Montgomery form transformation

			// Accumulate each share into the last party's share, P[len(P)-1].r, to ensure zero sum
			aggring.ringQ.Add(pi.r, P[len(P)-1].r, P[len(P)-1].r)
		}

		// Negate the accumulated value in the last party's share to achieve a zero-sum across all shares
		aggring.ringQ.Neg(P[len(P)-1].r, P[len(P)-1].r)

	}, len(P))
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Generates the input polynomials "mi" for each Data Owner Party P[i] and the expected aggregated result "aggexp"
// ----------------------------------------------------------------------------------------------//

// genInputs initializes the input "mi" for each party and obtains the expected aggregated result aggexp = m1 + m2 + ...
// Inputs:
//   - aggring: Aggregated ring structure containing necessary ring operations and parameters.
//   - lowNormUniformQ: Sampler to generate polynomials with coefficients bounded by a norm.
//   - n: Number of input polynomials to be generated per party.
//   - P: Array of parties participating in the protocol, each having an input "mi" to contribute.
//   - param: Struct containing cryptographic parameters, specifically the modulus level for polynomial generation.
// Outputs:
//   - aggexp: Array of polynomials representing the expected aggregate sum of inputs from all parties.
// ----------------------------------------------------------------------------------------------//

func genInputs(aggring *AggRings, lowNormUniformQ *lowNormSampler, n int, P []*party, param parameters) (aggexp []ring.Poly) {

	// Measure the elapsed time for input generation across all parties
	elapsedSetupParty += runTimedParty(func() {

		// Step 1: Initialize "aggexp" as an array of "n" polynomials to store the aggregate sum of each input polynomial across all parties
		aggexp = make([]ring.Poly, n)
		for i := 0; i < n; i++ {
			aggexp[i] = aggring.ringQ.NewPoly() // Allocate memory for each polynomial in aggexp
		}

		// Step 2: Generate input polynomials "mi" for each party and add them to "aggexp" to accumulate the expected aggregate result
		for _, pi := range P {
			pi.input = make([]ring.Poly, n) // Allocate memory for each party’s input polynomials
			for i := 0; i < n; i++ {
				// Sample a polynomial with coefficients bounded by "norm" (defined by modulus level "plevel")
				pi.input[i] = lowNormUniformQ.newPolyLowNorm(aggring.ringQ.ModulusAtLevel[param.plevel])

				// Convert polynomial to NTT domain for efficient addition and storage in "aggexp"
				aggring.ringQ.NTT(pi.input[i], pi.input[i])

				// Add the current party's input to the cumulative aggregate result "aggexp"
				aggring.ringQ.Add(pi.input[i], aggexp[i], aggexp[i])
			}
		}

		// Step 3: Convert each polynomial in "aggexp" back to its standard form using INTT and resize to modulus level "plevel"
		for i := 0; i < n; i++ {
			aggring.ringQ.INTT(aggexp[i], aggexp[i]) // Transform back to standard domain
			aggexp[i].Resize(param.plevel)           // Adjust size to match the level "plevel"
		}

	}, len(P))

	// Output: Return the accumulated expected result "aggexp" containing the sum of each party's input polynomials
	return aggexp
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Generates the input Secret-Key ciphertexts "encInputs" + partial decryptions "partialDec"
// in parallel across multiple goroutines
// ----------------------------------------------------------------------------------------------//

// encPhaseParallel generates encrypted inputs and partial decryptions for each party in the protocol
// in a parallelized manner using multiple goroutines for enhanced performance. For each input "mi"
// of each party, this phase performs an encryption operation on the input using the party's secret
// key ("ski") and random share ("ri"). This process involves sampling a random polynomial "a",
// generating noise "ei", and applying modular transformations to secure the data before aggregation.
// Additionally, each party computes a partial decryption "pdi" share that will be used in the final
// decryption phase. The parallelization aims to optimize the processing time by distributing the
// workload across multiple goroutines.
//
// Inputs:
//   - aggring: Aggregated ring structure with necessary operations for encryption and decryption.
//   - PreComputeA: Flag indicating whether to precompute the polynomial "a" before encryption for
//     optimization purposes.
//   - NGoRoutine: Number of goroutines to be used for parallel processing.
//   - uniformSamplerQ: Sampler for generating uniform random polynomials "a" used in encryption.
//   - n: Number of input polynomials to generate per party.
//   - P: Array of parties participating in the protocol, each holding a secret key "sk" and a randomness "r".
//   - param: Struct containing cryptographic parameters, especially the prime modulus level for encryption.
//
// Outputs:
//   - encInputs: Array of encrypted input polynomials for each party, structured as encInputs[party][input].
//   - partialDec: Array of partial decryptions for each party, structured as partialDec[party][input].
func encPhaseParallel(aggring *AggRings, PreComputeA bool, NGoRoutine int, uniformSamplerQ ring.Sampler, n int, P []*party, param parameters) (encInputs [][]ring.Poly, partialDec [][]ring.Poly) { // to point or not to point, that's the question
	//pending to update -- gaussianSampler is generated inside..., while prng=crs is passed to generate the uniformSamplerQ inside in common

	elapsedSetupGaussianParty = time.Duration(0)
	elapsedPreprocessingEncryptParty = time.Duration(0)

	elapsedEncryptParty = time.Duration(0)
	elapsedEncryptPartyWall = time.Duration(0)
	elapsedEncryptPartyCPU = time.Duration(0)
	elapsedEncryptCloud = time.Duration(0)

	startSetupGaussian := time.Now()

	// Setup for Gaussian samplers per party for Go routines. A different gaussianSamplerQ per each Go routine
	gaussianSamplerQ := make([]ring.Sampler, NGoRoutine)
	for i := 0; i < NGoRoutine; i++ {
		prng, err := sampling.NewPRNG()
		check(err)
		gaussianSamplerQ[i], err = ring.NewSampler(prng, aggring.ringQ, ring.DiscreteGaussian{Sigma: 3.2, Bound: 19}, false) // NewPRNG() generates samplers with different keys
		check(err)
	}

	elapsedSetupGaussianParty = time.Duration(time.Since(startSetupGaussian).Nanoseconds())
	fmt.Printf("> (+ Prepare error gaussian Samplers in each party for Go routines: %s) - (no parallelization)\n", elapsedSetupGaussianParty)

	// Preprocessing to compute or allocate for 'a' values
	startPreprocessingEncrypt := time.Now()

	// Sample or preserve (depending on "PreComputeA") memory for different "a" per each consecutive correlated encryption (a total of "n")
	a := make([]ring.Poly, n) // must be measured as the runtime of only 1 party
	for j := 0; j < n; j++ {
		// Precompute or allocate 'a' values depending on PreComputeA flag
		// Next we choose whether we precompute the 'a' terms before starting measuring encryption runtime
		if PreComputeA {
			a[j] = uniformSamplerQ.ReadNew() // Sample uniform random polynomial
			aggring.ringQ.NTT(a[j], a[j])    // Convert to NTT domain for efficient operations
		} else {
			a[j] = aggring.ringQ.NewPoly() // Allocate new polynomials if not precomputing
		}

	}
	elapsedPreprocessingEncryptParty = time.Duration(time.Since(startPreprocessingEncrypt).Nanoseconds())

	var uniformSamplerQvec []ring.Sampler
	if PreComputeA {
		fmt.Printf("> (+ Preprocessing to generate 'a' components per party: %s) - (no parallelization)\n", elapsedPreprocessingEncryptParty)
	} else {
		// Set up uniform samplers for Go routines. A different uniformSamplerQ per each Go routine
		startPreprocessingUniformSamplersA := time.Now()
		uniformSamplerQvec = make([]ring.Sampler, NGoRoutine)
		for i := 0; i < NGoRoutine; i++ {
			crs, err := sampling.NewPRNG() // This generates a sampler with a random key for the keyedPRNG. The alternative option 'NewKeyedPRNG' allows to input "key"
			check(err)
			// Warning! This solution does not generate the same value 'a' in a correlated way among different Go routines (it is not relevant for correctness and runtime execution)=> to do this needed to synchronize Go routines and parties to generate the same value for the same index 'j'
			// Warning! 1 option: To correlate parties we could agree in "key" and choose newsampler with "key <- key + 1" for each new random polynomial (i.e., key + j for 'j'-th polynomial)
			// Warning! 2 option: Fix key and add a "counter of calls" Goroutine (i) with input (j) calls 'j'-times the function after reset (or the number of times required to have exactly 'j' calls)
			// Warning! Best option: Assign a subset n/NumGoRoutine per each Go routine. Each Go routine starts with a specific different "key" value or state. The order and "key" or state is shared among parties => this option has efficiency equivalent to the current implemented.

			uniformSamplerQvec[i], err = ring.NewSampler(crs, aggring.ringQ, ring.Uniform{}, false)
			check(err)
		}
		elapsedPreprocessingUniformSamplersParty = time.Duration(time.Since(startPreprocessingUniformSamplersA).Nanoseconds())

		fmt.Printf("> (+ Prepare uniform Samplers in each party for Go routines: %s) - (no parallelization)\n", elapsedPreprocessingUniformSamplersParty)

	}

	//elapsedEncryptParty += time.Since(start)

	// Parallel encryption phase
	elapsedEncryptParty += runTimedParty(func() {

		// Buffers for polynomial operations in parallel tasks
		arraybuff := make([]ring.Poly, NGoRoutine)
		arraytmp := make([]ring.Poly, NGoRoutine)

		// Initialize the buffers
		for i := 0; i < NGoRoutine; i++ {
			arraybuff[i] = aggring.ringQ.NewPoly()
			arraytmp[i] = aggring.ringQ.NewPoly()
		}

		// Initialize encInputs and partialDec arrays
		encInputs = make([][]ring.Poly, len(P))
		partialDec = make([][]ring.Poly, len(P))

		for i := 0; i < len(P); i++ {
			encInputs[i] = make([]ring.Poly, n)
			partialDec[i] = make([]ring.Poly, n)
			for j := 0; j < n; j++ {
				encInputs[i][j] = aggring.ringQ.NewPoly()
				partialDec[i][j] = aggring.ringQ.NewPoly()
			}
		}

		// Loop over each party and distribute the work
		for i := 0; i < len(P); i++ {

			// Encryption phase of party (i)
			// Split the task among the Go routines
			tasksEnc := make(chan *multTaskEnc)
			workersEnc := &sync.WaitGroup{}

			workersEnc.Add(NGoRoutine)

			// Start Go routines
			for k := 1; k <= NGoRoutine; k++ {
				go func(k int) {
					for task := range tasksEnc {
						task.elapsedTaskEnc = runTimedParty(func() {
							// Encryption and partial decryption operations

							// c = e (Generate Gaussian noise for ciphertext)
							gaussianSamplerQ[k-1].AtLevel(aggring.ringQ.MaxLevel()).ReadAndAdd(task.res1)

							// c = NTT(e) (Convert noise to NTT domain)
							aggring.ringQ.NTT(task.res1, task.res1)

							// tmp = NTT(m * Q/P) (Scaling the message by Q/P)
							aggring.ringQ.MulScalarBigint(task.op1, aggring.QDivP, arraytmp[k-1])

							// c = NTT(m * (Q/P) + e) (Add scaled message to noise)
							aggring.ringQ.Add(task.res1, arraytmp[k-1], task.res1)

							// NTT(pdi) = NTT(a) * NTT(MF(ski)) = NTT(a * ski) (Partial decryption)
							if PreComputeA {
								aggring.ringQ.MulCoeffsMontgomery(task.op4, task.op2, task.res2)
							} else {
								// Sample a new "a" if not precomputing
								uniformSamplerQvec[k-1].ReadAndAdd(task.res2) // Warning! In real life we should force the same 'a' is generated when the same "j" index is used in the task
								aggring.ringQ.NTT(task.res2, task.res2)
								aggring.ringQ.MulCoeffsMontgomery(task.op4, task.res2, task.res2)
							}

							// c = NTT(m * (Q/P) + e) + NTT(a) * NTT(MF(ri)) (Adding share term of party i)
							// c = NTT(m * (Q/P) + e) + NTT(a) * MForm(NTT(ri))
							// c = NTT(m * (Q/P) + e + a*ri)
							aggring.ringQ.MulCoeffsMontgomery(task.op2, task.op3, arraytmp[k-1])
							aggring.ringQ.Add(arraytmp[k-1], task.res1, task.res1)

							// c = NTT(m * (Q/P) + e + a * ri + a * ski) (Complete ciphertext)
							aggring.ringQ.Add(task.res1, task.res2, task.res1)

							// Final step: computed NTT(a * ski) = pd[i] -> NTT(round(P'/Q * pd[i]))
							aggring.ringQ.AtLevel(aggring.ringQ.MaxLevel()).DivRoundByLastModulusManyNTT(aggring.ringQ.MaxLevel()-param.pprimelevel, task.res2, arraybuff[k-1], task.res2)
							task.res2.Resize(param.pprimelevel)

						}, len(P))
						task.wg.Done()
					}
					workersEnc.Done()
				}(k)
			}

			// Generate tasks for each encryption step
			taskListEnc := make([]*multTaskEnc, 0) // taskList type (2)

			elapsedEncryptPartyWall += runTimedParty(func() {
				// Launch tasks for Encryption and Partial Decryption
				wg := &sync.WaitGroup{}
				wg.Add(n)

				// Loop through all ciphertexts per party
				for j := 0; j < n; j++ {
					taskEnc := multTaskEnc{wg, P[i].input[j], a[j], P[i].r, P[i].sk, encInputs[i][j], partialDec[i][j], 0} // Warning! In real life should include the "a index 'j'" and "counter of calls" to be used as input to the Go routine Samplers and force they are correlated
					taskListEnc = append(taskListEnc, &taskEnc)
					tasksEnc <- &taskEnc
				}
				wg.Wait()

				// Collect the elapsed time for the tasks
				for _, t := range taskListEnc {
					elapsedEncryptPartyCPU += t.elapsedTaskEnc
				}

			}, len(P))

			// Shut down workers after all tasks are done
			close(tasksEnc)
			workersEnc.Wait()

		}

		// Print final elapsed times
		fmt.Println("\n> Parallel Encryption Phase")
		fmt.Printf("\tWork done (CPU time party: %s (wall: %s), party: %s)\n",
			elapsedEncryptPartyCPU, elapsedEncryptPartyWall, elapsedEncryptCloud)

	}, len(P))

	return encInputs, partialDec
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Computes the aggregation c0 + c1 + ... + c_{L - 1} = cagg with several Go routines
// ----------------------------------------------------------------------------------------------//

// evalPhaseParallel aggregates encrypted inputs from each party into a single encrypted sum
// in a parallelized manner using multiple goroutines for enhanced performance. This function
// takes multiple ciphertexts from each party, performs polynomial arithmetic, and sums them
// to produce an aggregate ciphertext "cagg", which represents the total encrypted data across
// all parties. The parallelization optimizes the aggregation process by distributing the workload
// across multiple goroutines, speeding up the computation, especially for large datasets or
// a high number of parties.
//
// Inputs:
//   - aggring: Aggregated ring structure containing operations required for polynomial arithmetic.
//   - n: The number of encrypted inputs per party.
//   - NGoRoutine: Number of goroutines to be used for parallel processing, distributing the aggregation work.
//   - encInput: A 2D array of encrypted polynomials, where encInput[party][input] represents
//     the encrypted input from each party for each data point.
//   - param: Parameter structure holding encryption settings and the target modulus level.
//
// Outputs:
//   - encShareAgg: Array of aggregated polynomials, where each entry corresponds to the sum of
//     encrypted inputs for a given data point across all parties, computed in parallel.
func evalPhaseParallel(aggring *AggRings, n int, NGoRoutine int, encInput [][]ring.Poly, param parameters) (encShareAgg []ring.Poly) {

	// Initialize elapsed time trackers for the evaluation process
	elapsedEvalCloud = time.Duration(0)
	elapsedEvalCloud += runTimed(func() {

		// Create a buffer array for intermediate polynomial operations, one per goroutine
		arraybuff := make([]ring.Poly, NGoRoutine)
		for i := 0; i < NGoRoutine; i++ {
			arraybuff[i] = aggring.ringQ.NewPoly()
		}

		// Initialize the output slice to store aggregated ciphertexts for each input
		encShareAgg = make([]ring.Poly, n)
		for i := 0; i < n; i++ {
			encShareAgg[i] = aggring.ringQ.NewPoly()
		}

		// Generate "SizeEncLayers" structure. Precompute layer sizes for the aggregation tree structure
		SizeEncLayers := make([]int, 0)
		SizeEncLayers = append(SizeEncLayers, len(encInput)) // Initial size equals the number of parties
		endingLayersStructure := 0                           // endingLayersStructure is equal to 1, when nLayer = 1
		for nLayer := (len(encInput)/2 + (len(encInput) & 1)); (nLayer > 0) && (endingLayersStructure == 0); nLayer = ((nLayer >> 1) + (nLayer & 1)) {
			if nLayer == 1 {
				endingLayersStructure = 1 // Mark the final layer
			}
			SizeEncLayers = append(SizeEncLayers, nLayer)
		}

		// (1) Homomorphic Addition phase of aggregation
		// Split the task among the Go routines
		// Create a channel for tasks and a WaitGroup to synchronize goroutines
		tasks := make(chan *multTask)
		workers := &sync.WaitGroup{}
		workers.Add(NGoRoutine)

		// Launch goroutines to process addition tasks in parallel
		for i := 1; i <= NGoRoutine; i++ {
			go func(i int) {
				for task := range tasks {
					task.elapsedTask = runTimed(func() {
						// Perform homomorphic addition for each ciphertext in the task
						for indCiphertext := range task.op1 {
							aggring.ringQ.Add(task.op1[indCiphertext], task.op2[indCiphertext], task.res[indCiphertext])
						}
					})
					task.wg.Done() // Mark the task as done
				}
				workers.Done() // Indicate this worker is done
			}(i)
		}

		// (2) Rounding phase of aggregation
		// Split the task among the Go routines
		// Create a channel for rounding tasks and another WaitGroup
		tasksRounding := make(chan *multTaskRounding)
		workersRounding := &sync.WaitGroup{}

		workersRounding.Add(NGoRoutine)

		// Launch goroutines to process rounding tasks in parallel
		for i := 1; i <= NGoRoutine; i++ {
			go func(i int) {
				for task := range tasksRounding {
					task.elapsedTaskRounding = runTimed(func() {
						// Reduce the modulus level of the polynomial to fit the target level
						aggring.ringQ.AtLevel(aggring.ringQ.MaxLevel()).DivRoundByLastModulusManyNTT(aggring.ringQ.MaxLevel()-param.pprimelevel, task.op, arraybuff[i-1], task.op)
						task.op.Resize(param.pprimelevel) // Resize to the target modulus level

					})
					task.wg.Done()
				}
				workersRounding.Done() // Indicate this worker is done
			}(i)
		}

		// Task execution and synchronization
		// Start the tasks (first type (1), then type (2))
		taskList := make([]*multTask, 0)                 // Tasks for the addition phase -> taskList type (1)
		taskListRounding := make([]*multTaskRounding, 0) // Tasks for the rounding phase -> taskList type (2)

		fmt.Printf("\n> Parallel Evaluation Phase\n")

		scale := 2
		shift := 1

		// Measure wall-clock time for the entire aggregation phase
		elapsedEvalCloudWall = time.Duration(0)
		elapsedEvalCloudWall = runTimed(func() {

			// Launch addition tasks type (1)
			for i, layer := range SizeEncLayers[:len(SizeEncLayers)-1] {

				nextLayer := SizeEncLayers[i+1]
				fmt.Println("\tWork type (1): Encrypted model updates added in layer", i, ":", layer, "->", nextLayer)
				wg := &sync.WaitGroup{}

				wg.Add(layer / 2) // Number of tasks to synchronize for this layer

				for j := 0; j < nextLayer; j++ {
					if !((2 * nextLayer) > layer) || !(j == (nextLayer - 1)) {
						task := multTask{wg, encInput[scale*j], encInput[scale*j+shift], encInput[scale*j], 0}
						taskList = append(taskList, &task)
						tasks <- &task
					}
				}
				wg.Wait() // Wait for tasks in the current layer to complete
				scale = 2 * scale
				shift = 2 * shift
			}

			// Compute elapsed CPU time for the addition phase
			elapsedEvalCloudCPU = time.Duration(0)
			for _, t := range taskList {
				elapsedEvalCloudCPU += t.elapsedTask
			}

			// Shutdown addition workers
			close(tasks)
			workers.Wait()

			// Launch rounding tasks type (2)
			fmt.Println("\tWork type (2): Q -> P' Rounding in process")
			wg := &sync.WaitGroup{}
			wg.Add(n) // One task per data point

			for j := 0; j < n; j++ { // running through all ciphertexts per party
				taskRounding := multTaskRounding{wg, encInput[0][j], 0}
				taskListRounding = append(taskListRounding, &taskRounding)
				tasksRounding <- &taskRounding
			}
			wg.Wait() // Wait for rounding tasks to complete

			// Compute elapsed CPU time for the rounding phase
			for _, t := range taskListRounding {
				elapsedEvalCloudCPU += t.elapsedTaskRounding
			}

		})

		// Finalize and print performance metrics
		elapsedEvalParty = time.Duration(0)
		fmt.Printf("\tWork done (CPU time cloud: %s (wall: %s), party: %s)\n",
			elapsedEvalCloudCPU, elapsedEvalCloudWall, elapsedEvalParty)

		// Shutdown rounding workers
		close(tasksRounding)
		workersRounding.Wait()

		// Store the final aggregation result in "encShareAgg"
		encShareAgg = encInput[0]
	})

	return encShareAgg
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Gathers all partial decryptions "partialDec" together with "encShareAgg" to obtain the result
// using multiple Go routines for parallel processing
// ----------------------------------------------------------------------------------------------//

// decPhaseParallel combines all partial decryptions from each party with the aggregated encrypted
// share "encShareAgg" to compute the final decrypted result in parallel. This function performs
// the decryption operation using the accumulated partial decryptions and the aggregated ciphertexts
// in a parallelized manner, optimizing the decryption process by distributing the workload across
// multiple goroutines. The parallelization significantly improves performance, especially when handling
// a large number of parties or complex datasets. The final decrypted result "recShare" is securely
// reconstructed by combining the contributions of all parties in parallel.
//
// Inputs:
//   - aggring: Aggregated ring structure containing operations required for polynomial arithmetic.
//   - NGoRoutine: Number of goroutines to be used for parallel processing, distributing the decryption
//     work efficiently across multiple threads.
//   - partialDec: A 2D array of partial decryptions from each party, where partialDec[party][input]
//     represents the partial decryption share for each data point from each party.
//   - encShareAgg: Array of aggregated encrypted polynomials, representing the sum of encrypted inputs
//     across all parties for a given data point.
//   - n: The number of encrypted inputs per party.
//   - param: Parameter structure holding encryption settings and the target modulus level.
//
// Outputs:
//   - recShare: Array of decrypted polynomials, where each entry corresponds to the final decrypted
//     result after combining all partial decryptions and the aggregated encrypted share,
//     computed in parallel.
func decPhaseParallel(aggring *AggRings, NGoRoutine int, partialDec [][]ring.Poly, encShareAgg []ring.Poly, n int, param parameters) (recShare []ring.Poly) {

	// Assumes that messages are masked with known randomness by all input parties,
	// allowing the cloud to securely perform decryption.

	// Initialize a timer to measure the decryption phase duration.
	elapsedDecCloud = time.Duration(0)
	elapsedDecCloud += runTimed(func() {

		// (1) Preparation: Initialize data structures
		// Polynomials to store the decrypted results.
		recShare = make([]ring.Poly, n)
		for j := 0; j < n; j++ { // running through ciphertexts per party

			recShare[j] = aggring.ringQ.AtLevel(param.pprimelevel).NewPoly()
		}

		// Temporary buffers for each goroutine.
		arraybuff := make([]ring.Poly, NGoRoutine)
		for i := 0; i < NGoRoutine; i++ {
			arraybuff[i] = aggring.ringQ.NewPoly()
		}

		/*recShare = make([]ring.Poly, n) //encShare...
		for i := 0; i < n; i++ {
			recShare[i] = aggring.ringQ.NewPoly()
		}*/

		// Generate "SizeEncLayers" structure. Layer structure for partial decryption.
		SizeDecLayers := make([]int, 0)
		SizeDecLayers = append(SizeDecLayers, len(partialDec))
		endingLayersStructure := 0 // endingLayersStructure is equal to 1, when nLayer = 1
		for nLayer := (len(partialDec)/2 + (len(partialDec) & 1)); (nLayer > 0) && (endingLayersStructure == 0); nLayer = ((nLayer >> 1) + (nLayer & 1)) {
			if nLayer == 1 {
				endingLayersStructure = 1
			}
			SizeDecLayers = append(SizeDecLayers, nLayer)
		}

		// (1) Gathering of partial decryptions
		// Split the task among the Go routines
		// Create channels to distribute tasks to goroutines.
		tasks := make(chan *multTask)
		workers := &sync.WaitGroup{}
		workers.Add(NGoRoutine)

		// Launch goroutines for adding partial decryptions.
		for i := 1; i <= NGoRoutine; i++ {
			go func(i int) {
				for task := range tasks {
					task.elapsedTask = runTimed(func() {
						// Addition of two input vectors of ciphertexts
						for indCiphertext := range task.op1 {
							_ = indCiphertext
							aggring.ringQ.AtLevel(param.pprimelevel).Add(task.op1[indCiphertext], task.op2[indCiphertext], task.res[indCiphertext])
						}
					})
					task.wg.Done()
				}
				workers.Done()
			}(i)
		}

		// (2) Rounding phase of decryption
		// Split the task among the Go routines
		// Create channels for the rounding phase.
		tasksRoundingDec := make(chan *multTaskRoundingDec)
		workersRoundingDec := &sync.WaitGroup{}

		workersRoundingDec.Add(NGoRoutine)

		// Launch goroutines for rounding and modulus reduction.
		for i := 1; i <= NGoRoutine; i++ {
			go func(i int) {
				for task := range tasksRoundingDec {
					task.elapsedTaskRoundingDec = runTimed(func() {
						// Subtraction of two input vectors of ciphertexts
						aggring.ringQ.AtLevel(param.pprimelevel).Sub(task.op1, task.op2, task.res)
						aggring.ringQ.AtLevel(param.pprimelevel).DivRoundByLastModulusManyNTT(param.pprimelevel-param.plevel, task.res, arraybuff[i-1], task.res)
						task.res.Resize(param.plevel)
						aggring.ringQ.AtLevel(param.plevel).INTT(task.res, task.res)
					})
					task.wg.Done()
				}
				workersRoundingDec.Done()
			}(i)
		}

		// Start the tasks (first type 1, then type 2)
		taskList := make([]*multTask, 0)                       // taskList type(1)
		taskListRoundingDec := make([]*multTaskRoundingDec, 0) // taskList type (2)

		fmt.Printf("\n> Parallel Partial Decryption Gathering Phase\n")

		scale := 2
		shift := 1

		elapsedDecCloudWall = time.Duration(0)
		elapsedDecCloudWall = runTimed(func() {

			// Launch tasks type (1)
			for i, layer := range SizeDecLayers[:len(SizeDecLayers)-1] {

				nextLayer := SizeDecLayers[i+1]
				fmt.Println("\tWork type (1): Added partial decryptions in layer", i, ":", layer, "->", nextLayer)
				wg := &sync.WaitGroup{}

				wg.Add(layer / 2)

				for j := 0; j < nextLayer; j++ {
					if !((2 * nextLayer) > layer) || !(j == (nextLayer - 1)) {
						task := multTask{wg, partialDec[scale*j], partialDec[scale*j+shift], partialDec[scale*j], 0}
						taskList = append(taskList, &task)
						tasks <- &task
					}
				}
				wg.Wait()
				scale = 2 * scale
				shift = 2 * shift
			}

			elapsedDecCloudCPU = time.Duration(0)
			for _, t := range taskList {
				elapsedDecCloudCPU += t.elapsedTask
			}

			close(tasks)
			workers.Wait()

			// Intermediate phase (1.5): combining "encrypted aggregation" and "gathering of partial decryptions"
			// encShareAgg[j] - partialDec[0][j] -> recShare[j]

			// Launch tasks type (2)
			fmt.Println("\tWork type (2): P' -> P Rounding in process")
			wg := &sync.WaitGroup{}
			wg.Add(n)

			for j := 0; j < n; j++ { // running through all ciphertexts per party
				taskRoundingDec := multTaskRoundingDec{wg, encShareAgg[j], partialDec[0][j], recShare[j], 0}
				taskListRoundingDec = append(taskListRoundingDec, &taskRoundingDec)
				tasksRoundingDec <- &taskRoundingDec
			}
			wg.Wait()

			for _, t := range taskListRoundingDec {
				elapsedDecCloudCPU += t.elapsedTaskRoundingDec
			}

		})

		elapsedDecParty = time.Duration(0)
		fmt.Printf("\tWork done (CPU time cloud: %s (wall: %s), party: %s)\n",
			elapsedDecCloudCPU, elapsedDecCloudWall, elapsedDecParty)

		close(tasksRoundingDec)
		workersRoundingDec.Wait()

	})

	// Return the decrypted results.
	return recShare
}

// ----------------------------------------------------------------------------------------------//
