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
//			go run ./mkAgg.go -commandline -numparties 10 -numctxperparty 2 -qlevel 2 -pprimelevel 1 -plevel 0 -logN 11 -bitlevelsize 30
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
	NumParties  int
	n           int // n = Number of ciphertexts per party to aggregate in each round (n*N corresponds to the "Size" of the model to aggregate)
	PreComputeA bool

	// Cryptographic parameters
	logN        int    // quotient polynomial Ring degree
	logQ        [2]int // logQ[0] = #Primes, logQ[1] = Primes bit-size
	pprimelevel int    // pprimelevel = plevel + 1
	plevel      int    // Maximum level for the modulus "p" (level 0 is the lowest available level)
}

// benchParameters: configuration of multiple aggregations to be tested. Used with go run ./mkAgg.go
var benchParameters = []parameters{

	// Parameter set 1 in report
	{NumParties: 16, n: 128, PreComputeA: false, logN: 13, logQ: [2]int{9, 22}, pprimelevel: 1, plevel: 0},
	//{NumParties: 16, n: 128, PreComputeA: false, logN: 13, logQ: [2]int{9, 22}, pprimelevel: 1, plevel: 0},
	//{NumParties: 16, n: 128, PreComputeA: false, logN: 13, logQ: [2]int{9, 22}, pprimelevel: 1, plevel: 0},

	// Parameter set 2 in report
	//{NumParties: 16, n: 128, PreComputeA: false, logN: 13, logQ: [2]int{7, 30}, pprimelevel: 1, plevel: 0},
	//{NumParties: 16, n: 128, PreComputeA: false, logN: 13, logQ: [2]int{7, 30}, pprimelevel: 1, plevel: 0},
	//{NumParties: 16, n: 128, PreComputeA: false, logN: 13, logQ: [2]int{7, 30}, pprimelevel: 1, plevel: 0},

	// Parameter set 3 in report
	//{NumParties: 16, n: 64, PreComputeA: false, logN: 14, logQ: [2]int{8, 30}, pprimelevel: 2, plevel: 1},
	//{NumParties: 16, n: 64, PreComputeA: false, logN: 14, logQ: [2]int{8, 30}, pprimelevel: 2, plevel: 1},
	//{NumParties: 16, n: 64, PreComputeA: false, logN: 14, logQ: [2]int{8, 30}, pprimelevel: 2, plevel: 1},

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
// (1) From command line parameters: go run ./mkAgg.go -commandline -numparties 10 -numctxperparty 2 -qlevel 2 -pprimelevel 1 -plevel 0 -logN 11 -bitlevelsize 30
// (2) From parameters in benchParameters: go run ./mkAgg.go
func main() {

	// ----------------------------------------------------------------------------------------------//
	// For more details about the multi-key secure aggregation rule with HE, see the preliminary work "Practical Multi-Key Homomorphic Encryption for More Flexible and Efficient Secure Federated Average Aggregation"
	// (<https://ieeexplore.ieee.org/document/10224979> or <https://eprint.iacr.org/2022/1674>)
	// ----------------------------------------------------------------------------------------------//
	// $go run main.go -commandline arg1 arg2 arg3 ...
	//  -numparties: number of parties
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
		n := param.n                     // Number of ciphertexts per party to aggregate
		qlevel := ringQ.MaxLevel()       // Maximum level for the ciphertext ring modulus
		pprimelevel := param.pprimelevel // p' modulus level
		plevel := param.plevel           // p modulus level
		levelsize := param.logQ[1]       // Bit size of the modulus primes
		NumParties := param.NumParties   // Number of parties in the protocol
		PreComputeA := param.PreComputeA // Flag for pre-computation optimization
		_ = PreComputeA

		// Display protocol and cryptographic parameter details
		fmt.Printf("\n-----------------------------------------------------------------------------------------------\n")
		fmt.Printf("Protocol Parameters:\n>>> Nparties=%d Ctxs.Round=%d", NumParties, n)
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
		encInput, partialDec := encPhase(priaggrings, gaussianSamplerQ, uniformSamplerQ, n, P, param) // Perform encryption without Goroutines, sharing the prng for uniform sampling (uniformSamplerQ) across parties
		//PENDING UPDATE receiving only inputs from P[i], uniformSamplerQ from the same crs and a fresh gaussianSamplerQ
		//PENDING UPDATE run loop "for i := 0; i < n; i++ { encInputi, particDeci := encPhase(priaggrings, gaussianSamplerQ, uniformSamplerQ, n, P[i], param) }"

		// Output message indicating the completion of the encryption phase for both cloud and party components
		fmt.Printf("\n> Encryption done (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

		// ----------------------------------------------------------------------------------------------//

		// ----------------------------------------------------------------------------------------------//
		// 3. AGGREGATION PHASE
		// ----------------------------------------------------------------------------------------------//

		// Aggregation phase:
		// Inputs => c0, c1, ..., c_{L - 1} (ciphertexts from all parties)
		// Outputs => cagg = c0 + c1 + ... + c_{L - 1} (aggregated ciphertext result)

		encShareAgg := evalPhase(priaggrings, n, encInput, param) // Perform aggregation without Goroutines across cloud workers

		// Output message indicating the completion of the aggregation phase for both cloud and party components
		fmt.Printf("\n> Aggregation done (cloud: %s, party: %s)\n", elapsedEvalCloud, elapsedEvalParty)

		// ----------------------------------------------------------------------------------------------//

		// ----------------------------------------------------------------------------------------------//
		// 3. DECRYPTION PHASE
		// ----------------------------------------------------------------------------------------------//

		//decPhase:
		// Inputs => partialdec(a, sk_i) (partial decryption of each party's input), aggoutputenc (aggregated encrypted ciphertext)
		// Outputs => recAggShare = partialdec(a,sk_i) + aggoutputenc (reconstructed aggregated result after decryption)

		recAggShare := decPhase(priaggrings, partialDec, encShareAgg, n, param) // Perform decryption and aggregation without Goroutines across cloud workers

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
// ----------------------------------------------------------------------------------------------//

// encPhase generates encrypted inputs and partial decryptions for each party in the protocol.
// For each input "mi"" of each party, this phase performs an encryption operation on the input
// using the party's secret key ("ski") and random share ("ri"). This process involves sampling a
// random polynomial "a", generating noise "ei", and applying modular transformations to
// secure the data before aggregation. Additionally, each party computes a partial decryption "pdi" share
// that will be used in the final decryption phase.
// Inputs:
//   - aggring: Aggregated ring structure with necessary operations for encryption and decryption.
//   - gaussianSamplerQ: Sampler for generating Gaussian noise polynomials.
//   - uniformSamplerQ: Sampler for generating uniform random polynomials "a" used in encryption.
//   - n: Number of input polynomials to generate per party.
//   - P: Array of parties participating in the protocol, each holding a secret key "sk" and a randomness "r".
//   - param: Struct containing cryptographic parameters, especially the prime modulus level for encryption.
//
// Outputs:
//   - encInputs: Array of encrypted input polynomials for each party, structured as encInputs[party][input].
//   - partialDec: Array of partial decryptions for each party, structured as partialDec[party][input].
func encPhase(aggring *AggRings, gaussianSamplerQ ring.Sampler, uniformSamplerQ ring.Sampler, n int, P []*party, param parameters) (encInputs [][]ring.Poly, partialDec [][]ring.Poly) { // to point or not to point, that's the question
	//POSSIBLE UPDATE => gaussianSampler is generated inside..., while prng=crs is passed to generate the uniformSamplerQ inside in common

	// Measure elapsed time for encryption phase across all parties
	elapsedEncryptParty = time.Duration(0)
	elapsedEncryptParty += runTimedParty(func() {

		// Temporary buffers for polynomial operations
		buff := aggring.ringQ.NewPoly() // Buffer for intermediate storage
		tmp := aggring.ringQ.NewPoly()  // Temporary polynomial for computation steps

		// Initialize arrays to hold encrypted inputs and partial decryptions for each party
		encInputs = make([][]ring.Poly, len(P))
		partialDec = make([][]ring.Poly, len(P))
		for i := 0; i < len(P); i++ {
			encInputs[i] = make([]ring.Poly, n)
			partialDec[i] = make([]ring.Poly, n)
		}

		// Step 1: Loop over each input index "j" to sample random polynomials "a" for encryption. Sample different "a" per each consecutive correlated encryption (a total of "n")
		for j := 0; j < n; j++ {

			// Encryption: a*(si + ri) + e + QDivP*m[i]
			a := uniformSamplerQ.ReadNew() // Sample a uniform random polynomial "a"
			aggring.ringQ.NTT(a, a)        // Convert "a" to NTT domain for efficient operations

			for i := 0; i < len(P); i++ { // Loop over each party to encrypt their inputs
				// c = e
				encInputs[i][j] = aggring.ringQ.NewPoly()
				gaussianSamplerQ.AtLevel(aggring.ringQ.MaxLevel()).ReadAndAdd(encInputs[i][j]) // Generate Gaussian noise "e"

				// c = NTT(e)
				aggring.ringQ.NTT(encInputs[i][j], encInputs[i][j]) // Convert noise to NTT domain

				// tmp = NTT(m * Q/P) for scaling
				aggring.ringQ.MulScalarBigint(P[i].input[j], aggring.QDivP, tmp)

				// c = NTT(m * (Q/P) + e)
				aggring.ringQ.Add(encInputs[i][j], tmp, encInputs[i][j]) // Add scaled message to noise

				// NTT(pdi) = NTT(a)*NTT(MF(ski))) = NTT(a*ski)
				partialDec[i][j] = aggring.ringQ.NewPoly()
				aggring.ringQ.MulCoeffsMontgomery(P[i].sk, a, partialDec[i][j])

				//ringQ.MForm(pd[i], pd[i])
				// c = NTT(m * (Q/P) + e) + NTT(a) * MForm(NTT(ri))
				// c = NTT(m * (Q/P) + e + a*ri)
				//ringQ.MForm(c[i], c[i])
				aggring.ringQ.MulCoeffsMontgomery(a, P[i].r, tmp) // Multiply "a" with party's randomness "r" and add to ciphertext
				aggring.ringQ.Add(tmp, encInputs[i][j], encInputs[i][j])

				// c = NTT(m * (Q/P) + e + a*ri + a*ski)
				aggring.ringQ.Add(encInputs[i][j], partialDec[i][j], encInputs[i][j]) // Complete encryption: add a*ski

				// computed NTT(a*ski) = pd[i] -> NTT(round(P'/Q*pd[i]))
				aggring.ringQ.AtLevel(aggring.ringQ.MaxLevel()).DivRoundByLastModulusManyNTT(aggring.ringQ.MaxLevel()-param.pprimelevel, partialDec[i][j], buff, partialDec[i][j])
				partialDec[i][j].Resize(param.pprimelevel) // Compute final partial decryption with modulus adjustment
				//}
			}
		}
	}, len(P))

	// Output: Return the encrypted inputs and the partial decryption shares for each party
	return encInputs, partialDec
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Computes the aggregation c0 + c1 + ... + c_{L - 1} = cagg
// ----------------------------------------------------------------------------------------------//

// evalPhase aggregates encrypted inputs from each party into a single encrypted sum.
// This function takes in multiple ciphertexts from each party and sums them to produce
// an aggregate ciphertext `cagg`, representing the total encrypted data of all parties.

// Inputs:
//   - aggring: Aggregated ring structure containing operations required for polynomial arithmetic.
//   - n: The number of encrypted inputs per party.
//   - encInput: A 2D array of encrypted polynomials, where encInput[party][input] represents
//               the encrypted input from each party for each data point.
//   - param: Parameter structure holding encryption settings and the target modulus level.

// Outputs:
//   - encShareAgg: Array of aggregated polynomials, where each entry corresponds to the sum of
//                  encrypted inputs for a given data point across all parties.

func evalPhase(aggring *AggRings, n int, encInput [][]ring.Poly, param parameters) (encShareAgg []ring.Poly) {

	// Measure and add time spent on this function to "elapsedEvalCloud"
	elapsedEvalCloud += runTimed(func() {

		// Initialize a buffer polynomial to temporarily hold intermediate calculations
		buff := aggring.ringQ.NewPoly()

		// Initialize "encShareAgg" to store the aggregated ciphertext for each input
		encShareAgg = make([]ring.Poly, n)
		for i := 0; i < n; i++ {
			encShareAgg[i] = aggring.ringQ.NewPoly() // Allocate space for each aggregate polynomial
		}

		// Aggregation process: iterate over each input index "j"
		for j := 0; j < n; j++ { // Loop through each ciphertext slot
			for i := 0; i < len(encInput); i++ { // Loop through each party
				// Add the encrypted input from party "i" to the aggregate for the current input "j"
				aggring.ringQ.Add(encInput[i][j], encShareAgg[j], encShareAgg[j])
			}

			// Adjust the aggregated polynomial to the target modulus level
			// Perform modulus reduction to fit within "pprimelevel"
			aggring.ringQ.AtLevel(aggring.ringQ.MaxLevel()).DivRoundByLastModulusManyNTT(
				aggring.ringQ.MaxLevel()-param.pprimelevel, encShareAgg[j], buff, encShareAgg[j])

			// Resize the polynomial to conform to the specified modulus level
			encShareAgg[j].Resize(param.pprimelevel)
		}
	})

	// Return the aggregated ciphertext array
	return encShareAgg
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Gathers all partial decryptions "partialDec" together with "encShareAgg" to obtain the result
// ----------------------------------------------------------------------------------------------//

// decPhase combines all partial decryptions from each party with the aggregated encrypted
// share "encShareAgg" to compute the final decrypted result in parallel.
//
// Inputs:
//   - aggring: Aggregated ring structure containing operations required for polynomial arithmetic.
//   - partialDec: A 2D array of partial decryptions from each party, where partialDec[party][input]
//     represents the partial decryption share for each data point from each party.
//   - encShareAgg: Array of aggregated encrypted polynomials, representing the sum of encrypted inputs
//     across all parties for a given data point.
//   - n: The number of encrypted inputs per party.
//   - param: Parameter structure holding encryption settings and the target modulus level.
//
// Outputs:
//   - recShare: Array of decrypted polynomials, where each entry corresponds to the final decrypted
//     result after combining all partial decryptions and the aggregated encrypted share.

// ----------------------------------------------------------------------------------------------//
// Gathers all partial decryptions "partialDec" together with "encShareAgg" to obtain the result
// ----------------------------------------------------------------------------------------------//
func decPhase(aggring *AggRings, partialDec [][]ring.Poly, encShareAgg []ring.Poly, n int, param parameters) (recShare []ring.Poly) {

	// Assumes that messages are masked with known randomness by all input parties,
	// allowing the cloud to securely perform decryption.

	// Initialize a timer to measure the decryption phase duration.
	elapsedDecCloud = time.Duration(0)
	elapsedDecCloud += runTimed(func() {

		buff := aggring.ringQ.NewPoly()

		// Preparation: Initialize data structures
		// Polynomials to store the decrypted results.
		recShare = make([]ring.Poly, n)

		for j := 0; j < n; j++ { // running through ciphertexts per party

			recShare[j] = aggring.ringQ.AtLevel(param.pprimelevel).NewPoly()

			// Aggregate shares
			// Store in recShare the content of encShareAgg
			aggring.ringQ.AtLevel(param.pprimelevel).Add(encShareAgg[j], recShare[j], recShare[j])
			for i := 0; i < len(partialDec); i++ {
				aggring.ringQ.AtLevel(param.pprimelevel).Sub(recShare[j], partialDec[i][j], recShare[j])
			}

			// Final rounding step: round(P/P' * result)
			aggring.ringQ.AtLevel(param.pprimelevel).DivRoundByLastModulusManyNTT(param.pprimelevel-param.plevel, recShare[j], buff, recShare[j])
			recShare[j].Resize(param.plevel)
			aggring.ringQ.AtLevel(param.plevel).INTT(recShare[j], recShare[j])

		}

	})

	// Return the decrypted results.
	return recShare
}

// ----------------------------------------------------------------------------------------------//
