package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
)

type forgeResult struct {
	msgString string
	sig       Signature
}

func tryNonce(nonce uint64, rows [][256]uint8, sigslice []Signature, fixedBits []uint8) (bool, Signature, string) {
	msgString := fmt.Sprintf("Emanoel forge %d", nonce)
	msg := GetMessageFromString(msgString)
	forgedRows := pickRows(msg)

	for _, v := range fixedBits {
		if forgedRows[v] != rows[0][v] {
			return false, Signature{}, ""
		}
	}

	var sig Signature
	for i := range 256 {
		desiredRow := forgedRows[i]
		// found := false
		for r := range rows {
			if rows[r][i] == desiredRow {
				sig.Preimage[i] = sigslice[r].Preimage[i]
				// found = true
				break
			}
		}

		// if !found {
		// 	return false, Signature{}, ""
		// }
	}
	fmt.Printf("Found nonce %d\n", nonce)
	return true, sig, msgString
}

/*
A note about the provided keys and signatures:
the provided pubkey and signature, as well as "HexTo___" functions may not work
with all the different implementations people could built.  Specifically, they
are tied to an endian-ness.  If, for example, you decided to encode your public
keys as (according to the diagram in the slides) up to down, then left to right:
<bit 0, row 0> <bit 0, row 1> <bit 1, row 0> <bit 1, row 1> ...

then it won't work with the public key provided here, because it was encoded as
<bit 0, row 0> <bit 1, row 0> <bit 2, row 0> ... <bit 255, row 0> <bit 0, row 1> ...
(left to right, then up to down)

so while in class I said that any decisions like this would work as long as they
were consistent... that's not actually the case!  Because your functions will
need to use the same ordering as the ones I wrote in order to create the signatures
here.  I used what I thought was the most straightforward / simplest encoding, but
endian-ness is something of a tabs-vs-spaces thing that people like to argue
about :).

So for clarity, and since it's not that obvious from the HexTo___ decoding
functions, here's the order used:

secret keys and public keys:
all 256 elements of row 0, most significant bit to least significant bit
(big endian) followed by all 256 elements of row 1.  Total of 512 blocks
of 32 bytes each, for 16384 bytes.
For an efficient check of a bit within a [32]byte array using this ordering,
you can use:
    arr[i/8]>>(7-(i%8)))&0x01
where arr[] is the byte array, and i is the bit number; i=0 is left-most, and
i=255 is right-most.  The above statement will return a 1 or a 0 depending on
what's at that bit location.

Messages: messages are encoded the same way the sha256 function outputs, so
nothing to choose there.

Signatures: Signatures are also read left to right, MSB to LSB, with 256 blocks
of 32 bytes each, for a total of 8192 bytes.  There is no indication of whether
the provided preimage is from the 0-row or the 1-row; the accompanying message
hash can be used instead, or both can be tried.  This again interprets the message
hash in big-endian format, where
    message[i/8]>>(7-(i%8)))&0x01
can be used to determine which preimage block to reveal, where message[] is the
message to be signed, and i is the sequence of bits in the message, and blocks
in the signature.

Hopefully people don't have trouble with different encoding schemes.  If you
really want to use your own method which you find easier to work with or more
intuitive, that's OK!  You will need to re-encode the key and signatures provided
in signatures.go to match your ordering so that they are valid signatures with
your system.  This is probably more work though and I recommend using the big
endian encoding described here.

*/

// Forge is the forgery function, to be filled in and completed.  This is a trickier
// part of the assignment which will require the computer to do a bit of work.
// It's possible for a single core or single thread to complete this in a reasonable
// amount of time, but may be worthwhile to write multithreaded code to take
// advantage of multi-core CPUs.  For programmers familiar with multithreaded code
// in golang, the time spent on parallelizing this code will be more than offset by
// the CPU time speedup.  For programmers with access to 2-core or below CPUs, or
// who are less familiar with multithreaded code, the time taken in programming may
// exceed the CPU time saved.  Still, it's all about learning.
// The Forge() function doesn't take any inputs; the inputs are all hard-coded into
// the function which is a little ugly but works OK in this assigment.
// The input public key and signatures are provided in the "signatures.go" file and
// the code to convert those into the appropriate data structures is filled in
// already.
// Your job is to have this function return two things: A string containing the
// substring "forge" as well as your name or email-address, and a valid signature
// on the hash of that ascii string message, from the pubkey provided in the
// signatures.go file.
// The Forge function is tested by TestForgery() in forge_test.go, so if you
// run "go test" and everything passes, you should be all set.
func Forge() (string, Signature, error) {
	// decode pubkey, all 4 signatures into usable structures from hex strings
	pub, err := HexToPubkey(hexPubkey1)
	if err != nil {
		panic(err)
	}

	sig1, err := HexToSignature(hexSignature1)
	if err != nil {
		panic(err)
	}
	sig2, err := HexToSignature(hexSignature2)
	if err != nil {
		panic(err)
	}
	sig3, err := HexToSignature(hexSignature3)
	if err != nil {
		panic(err)
	}
	sig4, err := HexToSignature(hexSignature4)
	if err != nil {
		panic(err)
	}

	var sigslice []Signature
	sigslice = append(sigslice, sig1)
	sigslice = append(sigslice, sig2)
	sigslice = append(sigslice, sig3)
	sigslice = append(sigslice, sig4)

	var msgslice []Message

	msgslice = append(msgslice, GetMessageFromString("1"))
	msgslice = append(msgslice, GetMessageFromString("2"))
	msgslice = append(msgslice, GetMessageFromString("3"))
	msgslice = append(msgslice, GetMessageFromString("4"))

	fmt.Printf("ok 1: %v\n", Verify(msgslice[0], pub, sig1))
	fmt.Printf("ok 2: %v\n", Verify(msgslice[1], pub, sig2))
	fmt.Printf("ok 3: %v\n", Verify(msgslice[2], pub, sig3))
	fmt.Printf("ok 4: %v\n", Verify(msgslice[3], pub, sig4))

	// var sig Signature

	var rows [][256]uint8

	rows = append(rows, pickRows(GetMessageFromString("1")))
	rows = append(rows, pickRows(GetMessageFromString("2")))
	rows = append(rows, pickRows(GetMessageFromString("3")))
	rows = append(rows, pickRows(GetMessageFromString("4")))

	var fixedBits []uint8
	for i := range 256 {
		baseValue := rows[0][i]
		isFixed := true
		for r := range rows {
			if rows[r][i] != baseValue {
				isFixed = false
				break
			}
		}
		if isFixed {
			fixedBits = append(fixedBits, uint8(i))
		}
	}

	// Implement this:
	/*
	// Precompute which bytes and which bits matter
type byteMask struct {
    byteIdx  uint8
    mask     uint8  // which bits are fixed
    expected uint8  // what those bits should be
}

// For each fixed bit, accumulate byte masks
var byteMasks [32]byteMask

for _, i := range fixedBits {
    byteIdx := i / 8
    bitIdx := i % 8
    byteMasks[byteIdx].mask |= (1 << (7 - bitIdx))
    if rows[0][i] == 1 {
        byteMasks[byteIdx].expected |= (1 << (7 - bitIdx))
    }
}

// In tryNonce, check only the bytes with fixed bits:
for byteIdx := range 32 {
    if byteMasks[byteIdx].mask != 0 {
        msgByte := msg[byteIdx]
        if (msgByte & byteMasks[byteIdx].mask) != byteMasks[byteIdx].expected {
            return false, Signature{}, ""
        }
    }
}
	*/

	for _, i := range fixedBits {
		byteIdx := i / 8
		bitIdx := i % 8
	}

	// fmt.Printf("rows1: %0b\n", rows1)
	// fmt.Printf("rows2: %0b\n", rows2)
	// fmt.Printf("rows3: %0b\n", rows3)
	// fmt.Printf("rows4: %0b\n", rows4)

	// begining of multithreaded code
	numWorkers := runtime.NumCPU()
	jobs := make(chan uint64, 1000) // Buffered channel for better throughput
	results := make(chan forgeResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var nonceCounter int64
	wg.Add(numWorkers)

	for range numWorkers {
		go func() {
			defer wg.Done()
			for nonce := range jobs {
				atomic.AddInt64(&nonceCounter, 1)
				select {
				case <-ctx.Done():
					return
				default:
				}

				ok, sig, msgString := tryNonce(nonce, rows, sigslice, fixedBits)
				if ok {
					select {
					case results <- forgeResult{msgString, sig}:
						cancel()
					case <-ctx.Done():
					}
					return
				}
			}
		}()
	}

	go func() {
		for nonce := uint64(0); ; nonce++ {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- nonce:
			}
		}
	}()

	res := <-results
	cancel()
	wg.Wait()
	fmt.Printf("Checked %d nonces\n", atomic.LoadInt64(&nonceCounter))

	return res.msgString, res.sig, nil
	// end of multithreaded code
}

// hint:
// (arr[i/8]>>(7-(i%8)))&0x01
