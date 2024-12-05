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
	"log"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// ----------------------------------------------------------------------------------------------//
// For more details see the report discussing the implementation runtimes of aggregation with baseline BFV
// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// BFVbaselineAgg.go can be run as: go run ./BFVbaselineAgg.go NumParties Goroutines NumModelParameters
// - By default: NumParties = 16, Goroutines = 1, NumModelParameters = 1048576
//
// Cryptosystem parameters are defined in "paramsDef"
// - By default:
//	paramsDef := heint.ParametersLiteral{
//		LogN:             13,
//		LogQ:             []int{22, 22, 22, 22, 22, 22},
//		LogP:             []int{31},
//		PlaintextModulus: 2752513, // 21*2^17 + 1
//	}
//
// ----------------------------------------------------------------------------------------------//
// Comments: The code of this script was started by relying on the Examples folder available in Lattigo "https://github.com/tuneinsight/lattigo"
// ----------------------------------------------------------------------------------------------//

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
	sk                       *rlwe.SecretKey       // sk_i (individual secret key of party P_i)
	ckgShare                 mhe.PublicKeyGenShare // Party share used during the generation of the collective public key
	input                    []uint64              // Unidimensional array containing the vector associated with the model update
	PaddedNumModelParameters int                   // Size of the vector of model updates with zero padding (till the next multiple of params.N())
}

// multTask: structure used for the parallelization with Go routines in aggregation phase
type multTask struct {
	wg              *sync.WaitGroup
	op1             []*rlwe.Ciphertext
	op2             []*rlwe.Ciphertext
	res             []*rlwe.Ciphertext
	elapsedmultTask time.Duration
}

// Definition of variables used to measure runtime for specific steps of the aggregation protocol
var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration
var elapsedDecCloud time.Duration
var elapsedDecParty time.Duration
var elapsedHomKeySwitchCloud time.Duration
var elapsedHomKeySwitchParty time.Duration

// ----------------------------------------------------------------------------------------------//
// For more details see the report discussing the implementation runtimes of aggregation with baseline BFV
// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// BFVbaselineAgg.go can be run as: go run ./BFVbaselineAgg.go NumParties Goroutines NumModelParameters
// - By default: NumParties = 16, Goroutines = 1, NumModelParameters = 1048576
//
// Cryptosystem parameters are defined in "paramsDef"
// - By default:
//	paramsDef := heint.ParametersLiteral{
//		LogN:             13,
//		LogQ:             []int{22, 22, 22, 22, 22, 22},
//		LogP:             []int{31},
//		PlaintextModulus: 2752513, // 21*2^17 + 1
//	}
//
// ----------------------------------------------------------------------------------------------//
// Comments: The code of this script was started by relying on the Examples folder available in Lattigo "https://github.com/tuneinsight/lattigo"
// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// For more details about multi-key secure aggregation with HE see the preliminary work "Practical Multi-Key Homomorphic Encryption for More Flexible and Efficient Secure Federated Average Aggregation"
// (<https://ieeexplore.ieee.org/document/10224979> or <https://eprint.iacr.org/2022/1674>)
// ----------------------------------------------------------------------------------------------//

// main function. Example executions:
// go run ./BFVbaselineAgg.go 16 1 1048576
func main() {

	// Configure a new logger to send messages to the standard error stream (stderr).
	l := log.New(os.Stderr, "", 0)

	// Default number of input parties. NumParties
	N := 16
	var err error

	// If at least one argument is provided, attempt to parse the first argument as an integer
	// to redefine the number of parties (N).
	if len(os.Args[1:]) >= 1 {
		N, err = strconv.Atoi(os.Args[1])
		check(err)
	}

	// Default number of goroutines to use.
	NGoRoutine := 1

	// If a second argument is provided, attempt to parse it as an integer
	// to redefine the number of goroutines.
	if len(os.Args[1:]) >= 2 {
		NGoRoutine, err = strconv.Atoi(os.Args[2])
		check(err)
	}

	// Default number of model parameters
	NumModelParameters := 1048576 // This equals 2^20

	// If a third argument is provided, attempt to parse it as an integer
	// to redefine the number of model parameters.
	if len(os.Args[1:]) >= 3 {
		NumModelParameters, err = strconv.Atoi(os.Args[3])
		check(err)
	}

	// Parameter set 1
	paramsDef := heint.ParametersLiteral{
		LogN:             13,
		LogQ:             []int{22, 22, 22, 22, 22, 22},
		LogP:             []int{31},
		PlaintextModulus: 2752513, // 21*2^17 + 1
	}

	// Parameter set 2
	/*paramsDef := heint.ParametersLiteral{
		LogN:             13,
		LogQ:             []int{30, 30, 30, 30, 30},
		LogP:             []int{31},
		PlaintextModulus: 754974721, // 45*2^24 + 1,
	}*/

	// Parameter set 3
	/*paramsDef := heint.ParametersLiteral{
		LogN:             13,
		LogQ:             []int{60, 60, 60},
		LogP:             []int{31},
		PlaintextModulus: 855683929200394241, // 95*2^53 + 1
	}*/

	// Initialize cryptographic parameters from "paramsDef"
	params, err := heint.NewParametersFromLiteral(paramsDef)
	check(err)

	// Create a cryptographic random source (CRS) with a keyed PRNG using a predefined seed.
	crs, err := sampling.NewKeyedPRNG([]byte{'b', 'a', 's', 'e', 'l', 'i', 'n', 'e'})
	check(err)

	// Initialize the encoder for encoding and decoding plaintexts
	encoder := heint.NewEncoder(params)

	// Generate target secret and public key pair for testing decryption and correctness
	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()

	// Create each party and allocate the memory for all the shares needed in the protocol
	P := genparties(params, N)
	l.Println("> Initialization of Parties")

	// Start the process, only 1 aggregation round is executed

	// Generate inputs and calculate the expected result for verification purposes.
	// The inputs are padded with zeros for proper encoding.
	expRes := genInputs(params, P, NumModelParameters, 0xffffffffffffffff)
	l.Printf("> Input generation\n \tNum parties: %d, PaddedwithZeros-NumModelParameters: %d\n", len(P), len(expRes))

	// 1) Collective public key generation: Perform collective key generation (CKG) to compute a public key shared by all parties.
	pk := ckgphase(params, crs, P)

	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud, elapsedRKGParty+elapsedCKGParty)

	// 2) Encryption phase: Each party encrypts their inputs using the shared public key.
	encInputs := encPhase(params, P, pk, encoder)

	// 3) Evaluation phase: Perform homomorphic aggregation on the encrypted inputs.
	encRes := evalPhase(params, NGoRoutine, encInputs)
	encInputs = nil

	// 4) Public Collective Key Switching (PCKS): Parties collaboratively switch the encrypted result to the target secret key.
	encOut := pcksPhase(params, tpk, encRes, P)
	encRes = nil
	P = nil
	l.Printf("Size of result\t: Number of ciphertexts: %d ciphertexts\n", len(encOut))

	// Decryption phase: Use the target secret key (tsk) to decrypt the final result.
	l.Println("> Decrypt Phase")
	decryptor := rlwe.NewDecryptor(params, tsk)

	// Prepare plaintexts to hold decrypted data.
	ptres := make([]*rlwe.Plaintext, len(encOut))
	for i := range encOut {
		ptres[i] = heint.NewPlaintext(params, params.MaxLevel())
	}

	// Only 1 decryption is run, but would be done by all parties who know the tsk. So we use runTimed instead of runTimedParty to measure the runtime
	elapsedDecParty = runTimed(func() {
		for i := range encOut {
			decryptor.Decrypt(encOut[i], ptres[i]) // Decrypt each ciphertext into plaintext
			encOut[i] = nil
		}
	})

	elapsedDecCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedDecCloud, elapsedDecParty)

	l.Println("> Result:")

	// Check the result
	// Decode plaintexts to retrieve the final result as a list of integers.
	res := make([]uint64, len(expRes))

	partialRes := make([]uint64, params.N()) // Temporary buffer for decoding.
	for i := range ptres {
		check(encoder.Decode(ptres[i], partialRes)) // Decode plaintext to uint64 values.
		ptres[i] = nil
		for j := range partialRes {
			res[(i*len(partialRes) + j)] = partialRes[j] // Copy values to the final result array.
		}
	}

	// Validate the result by comparing it against the expected result.
	for i := range expRes {
		if expRes[i] != res[i] {
			// Log error details if there is a mismatch.
			l.Printf("\tincorrect\n first error in position [%d]\n", i)
			l.Printf("> Finished (total cloud: %s, total party: %s)\n", elapsedCKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud, elapsedCKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)
			return
		}
	}
	// If all results match, log success.
	l.Println("\tcorrect")
	l.Printf("> Finished (total cloud: %s, total party: %s)\n", elapsedCKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud+elapsedDecCloud, elapsedCKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)
}

// ----------------------------------------------------------------------------------------------//
// Generates the individual secret key and input model updates of size "NumModelParameters"
// for each Data Owner Party P[i]
// ----------------------------------------------------------------------------------------------//

// genparties initializes each data owner party and generates their individual secret key.
// Inputs:
// - params: Cryptographic parameters necessary for key generation
// - N: Total number of data owner parties
// Outputs:
// - Returns an array of *party structures, each containing an initialized secret key for a data owner

func genparties(params heint.Parameters, N int) []*party {

	// Allocate memory for each party's structure and the necessary shares for protocol operations
	P := make([]*party, N)

	// Initialize each party and generate their individual secret keys
	for i := range P {
		pi := &party{}                                         // Create a new party instance
		pi.sk = rlwe.NewKeyGenerator(params).GenSecretKeyNew() // Generate a new secret key using the provided parameters
		P[i] = pi                                              // Assign the initialized party to the party array
	}

	return P // Return the array of initialized parties
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Generates the inputs for each data owner party P[i] and calculates the expected result.
// The inputs are randomized values constrained by the provided BoundInputs and the parameters of the model.
// ----------------------------------------------------------------------------------------------//

// genInputs initializes the input values for each party and computes the expected results based on
// the inputs from all parties.
// Inputs:
// - params: Cryptographic parameters required for padding and modular operations
// - P: Array of data owner parties, each containing an input for the model
// - NumModelParameters: Total number of model parameters (used to determine input padding size)
// - BoundInputs: Upper bound for random input generation
// Outputs:
// - expRes: A slice of uint64 values representing the aggregated expected result of all parties' inputs

func genInputs(params heint.Parameters, P []*party, NumModelParameters int, BoundInputs uint64) (expRes []uint64) {

	// Generate Inputs for each party
	for _, pi := range P {
		// Determine the number of model parameters to pad based on polynomial degree and model parameters
		if params.N() >= NumModelParameters { // If polynomial degree is greater than or equal to the number of model parameters, no padding is needed
			pi.PaddedNumModelParameters = params.N()
		} else { // If polynomial degree is less than the number of model parameters, calculate required padding
			pi.PaddedNumModelParameters = int(math.Ceil(float64(NumModelParameters)/float64(params.N()))) * params.N()
		}

		// Initialize the input array with one random value
		pi.input = make([]uint64, 1)
		// Generate a random input value constrained by BoundInputs and the modulus
		pi.input[0] = (sampling.RandUint64() % BoundInputs) % params.PlaintextModulus() // Note:To save memory only one random value is stored, which is increased in each subsequent position.
	}

	// Allocate memory for the expected result array
	expRes = make([]uint64, P[0].PaddedNumModelParameters)

	// Generate the Aggregation Expected Results by summing inputs from all parties
	for _, pi := range P {
		for i := 0; i < P[0].PaddedNumModelParameters; i++ {
			// Aggregate each party's input and apply modular arithmetic
			expRes[i] += pi.input[0] + uint64(i)%params.PlaintextModulus()
			expRes[i] %= params.PlaintextModulus() // Ensure the result is within the modulus
		}
	}

	// Return the aggregated expected result
	return
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Conducts the Collective Key Generation (CKG) phase where each party generates a share of the
// public key and aggregates the shares to form the final public key.
// ----------------------------------------------------------------------------------------------//

// ckgphase performs the Collective Key Generation (CKG) protocol, where each party generates
// its share of the public key and the shares are then combined to create the final public key.
// Inputs:
// - params: Cryptographic parameters required for key generation
// - crs: It is used for generating the common random polynomial
// - P: Array of data owner parties, each generating a share of the public key
// Outputs:
// - Returns the aggregated public key generated from all party shares

func ckgphase(params heint.Parameters, crs sampling.PRNG, P []*party) *rlwe.PublicKey {

	l := log.New(os.Stderr, "", 0)

	// Log the start of the CKG phase
	l.Println("> CKG Phase")

	// Initialize the public key generation protocol
	ckg := mhe.NewPublicKeyGenProtocol(params)

	// Allocate a combined share for the public key, initially empty
	ckgCombined := ckg.AllocateShare()

	// Allocate space for each party's share in the key generation
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}

	// Sample the crp from the crs
	crp := ckg.SampleCRP(crs)

	// Record the time taken for the party-side share generation phase
	elapsedCKGParty = runTimedParty(func() {

		// Each party generates its own share of the public key based on its secret key and the CRP
		for _, pi := range P {
			ckg.GenShare(pi.sk, crp, &pi.ckgShare)
		}
	}, len(P))

	// Create a new public key to hold the final result
	pk := rlwe.NewPublicKey(params)

	// Record the time taken for the cloud-side aggregation and public key generation
	elapsedCKGCloud = runTimed(func() {

		// Aggregate each party's share into the combined share
		for _, pi := range P {
			ckg.AggregateShares(pi.ckgShare, ckgCombined, &ckgCombined)
		}

		// Generate the final public key by using the combined share and the CRP
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	// Log the time spent on the cloud and party-side operations
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	// Return the final generated public key
	return pk
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Executes the encryption phase where each party encrypts its input data into ciphertexts using
// the public key. Each party’s input is divided into multiple ciphertexts based on the model's
// parameter size, and encryption is performed using the provided encoder.
// ----------------------------------------------------------------------------------------------//

// encPhase performs the encryption of each party's input data, where each input is split into
// multiple ciphertexts depending on the model's parameter size and the party's input vector.
// Inputs:
// - params: Cryptographic parameters necessary for the encryption
// - P: Array of data owner parties, each containing input data to be encrypted
// - pk: Public key used for encrypting the input data
// - encoder: Encoder used for encoding the input data into plaintexts before encryption
// Outputs:
// - encInputs: A 2D slice of ciphertexts, where each party's encrypted inputs are stored in ciphertexts

func encPhase(params heint.Parameters, P []*party, pk *rlwe.PublicKey, encoder *heint.Encoder) (encInputs [][]*rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Determine the number of ciphertexts each party needs to generate based on the number of model parameters
	NumCiphertextsPerParty := int(math.Ceil(float64(P[0].PaddedNumModelParameters) / float64(params.N())))

	// Initialize the encInputs 2D array to hold ciphertexts for each party and each model parameter
	// encInputs[i][j], i through Parties, j through Model parameters
	encInputs = make([][]*rlwe.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = make([]*rlwe.Ciphertext, NumCiphertextsPerParty)
	}

	// Initialize the ciphertexts with a default size
	for i := range encInputs {
		for j := range encInputs[i] {
			encInputs[i][j] = rlwe.NewCiphertext(params, 1, params.MaxLevel()) // Allocate a new ciphertext for each entry
		}
	}

	// Start the encryption phase
	l.Println("> Encrypt Phase")

	// Create an encryptor using the public key
	encryptor := rlwe.NewEncryptor(params, pk)

	// Create a plaintext object and an array to hold the input values for encryption
	pt := heint.NewPlaintext(params, params.MaxLevel())
	arrayinputs := make([]uint64, params.N())

	// Encrypt each party's inputs
	for i, pi := range P {
		for j := 0; j < NumCiphertextsPerParty; j++ {

			// Initialize the array for input values to 0
			for k := 0; k < params.N(); k++ {
				arrayinputs[k] = uint64(0)
			}

			// Fill the array with the input values for encryption
			for k := 0; k < params.N(); k++ {

				// Calculate the encrypted value based on party input, index, and modulus
				arrayinputs[k] += pi.input[0] + (uint64(k)+uint64(j*params.N()))%params.PlaintextModulus()
				arrayinputs[k] %= params.PlaintextModulus()
			}

			// Encrypt the input data for this party and store it in encInputs
			elapsedEncryptParty += runTimedParty(func() {
				check(encoder.Encode(arrayinputs, pt))        // Encode the input into the plaintext
				check(encryptor.Encrypt(pt, encInputs[i][j])) // Encrypt the plaintext and store the ciphertext
			}, len(P))

		}
	}

	// The aggregator does not participate in this phase, so elapsedEncryptCloud remains 0
	elapsedEncryptCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	// Return the array of ciphertexts generated by all parties
	return
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Executes the evaluation phase where encrypted model updates are combined across multiple layers.
// This phase performs additions of encrypted ciphertexts in parallel using multiple Go routines.
// ----------------------------------------------------------------------------------------------//

// evalPhase performs the evaluation of encrypted model updates in multiple layers. In each layer,
// ciphertexts from different parties are added together in parallel, and the result is propagated
// to the next layer. The task is split among multiple Go routines to improve performance.
// Inputs:
// - params: Cryptographic parameters necessary for the evaluation
// - NGoRoutine: Number of Go routines to use for parallel computation
// - encInputs: A 2D slice of ciphertexts, where each party's encrypted inputs are stored
// Outputs:
// - encRes: A slice of ciphertexts representing the final evaluation result

func evalPhase(params heint.Parameters, NGoRoutine int, encInputs [][]*rlwe.Ciphertext) (encRes []*rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Determine the number of layers needed for the evaluation, based on the number of inputs
	SizeEncLayers := make([]int, 0)
	SizeEncLayers = append(SizeEncLayers, len(encInputs))
	endingLayersStructure := 0 // // endingLayerStructure is set to 1 when only 1 layer remains (i.e., nLayer = 1)
	for nLayer := (len(encInputs)/2 + (len(encInputs) & 1)); (nLayer > 0) && (endingLayersStructure == 0); nLayer = ((nLayer >> 1) + (nLayer & 1)) {
		if nLayer == 1 {
			endingLayersStructure = 1
		}
		SizeEncLayers = append(SizeEncLayers, nLayer)
	}

	// Initialize the evaluator to handle the addition of ciphertexts
	evaluator := heint.NewEvaluator(params, nil)

	// Create a channel for task distribution among Go routines and a WaitGroup for synchronization
	tasks := make(chan *multTask)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)

	// Launch Go routines to process tasks in parallel
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // Create a shallow copy of the evaluator for this Go routine
			for task := range tasks {
				// Perform the addition of two encrypted ciphertexts in each task
				task.elapsedmultTask = runTimed(func() {
					for indCiphertext := range task.op1 {
						evaluator.Add(task.op1[indCiphertext], task.op2[indCiphertext], task.res[indCiphertext])
					}
				})
				task.wg.Done() // Signal the task is done
			}
			workers.Done() // Signal the Go routine has finished processing
		}(i)
	}

	// Start the evaluation tasks
	taskList := make([]*multTask, 0)
	l.Println("> Eval Phase")

	// Scale and shift values used to divide the input layers for processing
	scale := 2
	shift := 1

	// Execute the evaluation phase by adding encrypted ciphertexts across layers
	elapsedEvalCloud = runTimed(func() {
		for i, layer := range SizeEncLayers[:len(SizeEncLayers)-1] {

			nextLayer := SizeEncLayers[i+1]
			l.Println("\tEncrypted model updates added in layer", i, ":", layer, "->", nextLayer)
			wg := &sync.WaitGroup{}

			wg.Add(layer / 2) // Each layer will add pairs of ciphertexts

			for j := 0; j < nextLayer; j++ {
				// Skip certain tasks based on the layer size and index
				if !((2 * nextLayer) > layer) || !(j == (nextLayer - 1)) {
					// Create a task to add the ciphertexts from two input layers
					task := multTask{wg, encInputs[scale*j], encInputs[scale*j+shift], encInputs[scale*j], 0}
					taskList = append(taskList, &task)
					tasks <- &task // Send the task to be processed by a Go routine
				}
			}
			wg.Wait() // Wait for all tasks in the current layer to finish
			scale = 2 * scale
			shift = 2 * shift
		}
	})

	// Compute total time taken for the aggregator-side processing of the tasks
	elapsedEvalCloudCPU = time.Duration(0)
	for _, t := range taskList {
		elapsedEvalCloudCPU += t.elapsedmultTask
	}

	// There is no computation done by parties in this phase, so elapsedEvalParty is 0
	elapsedEvalParty = time.Duration(0)
	l.Printf("\tdone (cloud: %s (wall: %s), party: %s)\n",
		elapsedEvalCloudCPU, elapsedEvalCloud, elapsedEvalParty)

	// Close the task channel and wait for all workers to complete
	close(tasks)
	workers.Wait()

	// The final result of the evaluation is stored in the first element of the input array
	encRes = encInputs[0]
	encInputs = nil

	// Return the array of output ciphertexts generated by the aggregator
	return
}

// ----------------------------------------------------------------------------------------------//

// ----------------------------------------------------------------------------------------------//
// Performs the Public Collective Key Switching (PCKS) phase, where the global secret key
// is switched to the target public key for decryption. This phase updates encrypted results
// with new keys for decryption using the target public key.
// ----------------------------------------------------------------------------------------------//

// pcksPhase executes the collective public-key switching protocol (PCKS) to transform encrypted results
// under a collective secret key into ciphertexts that can be decrypted with the target secret key.
// The protocol is run in two phases: first, each party computes a share of the key switching operation,
// and then the cloud aggregates the shares and performs the final key switching operation.
// Inputs:
// - params: Cryptographic parameters required for the key switching operation
// - tpk: Target public key, whose corresponding secret key will be used for decryption
// - encRes: A slice of encrypted results that need to be switched to the target key
// - P: A slice of parties that hold the secret keys and will participate in the key switching
// Outputs:
// - encOut: A slice of ciphertexts after the key switching has been applied

func pcksPhase(params heint.Parameters, tpk *rlwe.PublicKey, encRes []*rlwe.Ciphertext, P []*party) (encOut []*rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// To reduce the use of memory: only two pcksShare and pcksCombined components are used. In practice, both should be an array of size NumParties and pcksShare should change for each party

	// Log that the PCKS phase is starting
	l.Println("> PCKS Phase")

	// Initialize the public key switch protocol with a discrete Gaussian distribution for sampling
	pcks, err := mhe.NewPublicKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: 1 << 64, Bound: 6 * (1 << 64)})
	check(err)

	// Allocate shares for the key switching operation (using a combined share for aggregation)
	pcksCombined := pcks.AllocateShare(params.MaxLevel()) // emulated protocol
	pcksShare := pcks.AllocateShare(params.MaxLevel())    // emulated protocol

	// Loop over each encrypted result (encRes) that needs to be switched to the target public key
	for i := range encRes {

		// Reallocate a new combined share for each encrypted result
		pcksCombined = pcks.AllocateShare(params.MaxLevel())

		// For each party, generate its share of the key switching operation
		for _, pi := range P {

			// Generate key switching share from the party's secret key
			elapsedPCKSParty += runTimedParty(func() {
				// Generate the share using the party's secret key and the target public key
				pcks.GenShare(pi.sk, tpk, encRes[i], &pcksShare) // "emulated protocol"
			}, len(P))

			// Aggregate the key switching shares in the aggregator side
			elapsedPCKSCloud += runTimed(func() {
				pcks.AggregateShares(pcksShare, pcksCombined, &pcksCombined) // "emulated protocol"

			})
		}

		// Perform the key switching operation to update the ciphertext with the new key
		elapsedPCKSCloud += runTimed(func() {
			pcks.KeySwitch(encRes[i], pcksCombined, encRes[i]) // Perform key switching on the ciphertext
		})

	}

	// The output of the phase is the modified ciphertexts (encRes) after the key switching
	encOut = encRes

	// Log the time taken for the cloud and party operations in the key switching phase
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

	// Return the array of updated ciphertexts
	return

}

// ----------------------------------------------------------------------------------------------//
