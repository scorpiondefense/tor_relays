// drbg_test_vectors.go
//
// Standalone Go program that generates test vectors for the obfs4 HashDrbg
// (SipHash-2-4 in OFB mode). Use these vectors to verify that the C++ obfs4
// DRBG implementation produces identical output.
//
// Build & run:
//   go mod init drbg_test_vectors
//   go mod tidy
//   go run drbg_test_vectors.go
//
// The DRBG matches lyrebird's common/drbg package:
//   seed [0:16]  -> SipHash-2-4 key (k0 || k1, little-endian uint64s)
//   seed [16:24] -> initial OFB state
//
//   NextBlock():
//     sip.Write(ofb[:])
//     ofb = sip.Sum(nil)[:8]   // Sum resets the hash after producing output
//     return ofb

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"

	"github.com/dchest/siphash"
)

// HashDrbg is a CSPRNG based on SipHash-2-4 in OFB (output feedback) mode.
type HashDrbg struct {
	sip hash.Hash64
	ofb [8]byte
}

// NewHashDrbg creates a new HashDrbg from a 24-byte seed.
//   seed[0:16]  = SipHash key (two little-endian uint64 words: k0, k1)
//   seed[16:24] = initial OFB state
func NewHashDrbg(seed [24]byte) *HashDrbg {
	d := &HashDrbg{}
	d.sip = siphash.New(seed[:16])
	copy(d.ofb[:], seed[16:24])
	return d
}

// NextBlock advances the DRBG by one step and returns the 8-byte output block.
func (d *HashDrbg) NextBlock() [8]byte {
	d.sip.Write(d.ofb[:])
	copy(d.ofb[:], d.sip.Sum(nil))
	var result [8]byte
	copy(result[:], d.ofb[:])
	return result
}

func main() {
	// Construct a deterministic 24-byte seed: {0, 1, 2, ..., 23}.
	var seed [24]byte
	for i := 0; i < 24; i++ {
		seed[i] = byte(i)
	}

	fmt.Println("=== obfs4 HashDrbg (SipHash-2-4 OFB) Test Vectors ===")
	fmt.Println()

	// Print the seed for reference.
	fmt.Printf("Seed (%d bytes): %s\n", len(seed), hex.EncodeToString(seed[:]))
	fmt.Printf("  SipHash key  [0:16] : %s\n", hex.EncodeToString(seed[:16]))
	fmt.Printf("  Initial OFB [16:24] : %s\n", hex.EncodeToString(seed[16:24]))
	fmt.Println()

	// Also print the key as two little-endian uint64s, which is how
	// dchest/siphash interprets the 16-byte key internally.
	k0 := binary.LittleEndian.Uint64(seed[0:8])
	k1 := binary.LittleEndian.Uint64(seed[8:16])
	fmt.Printf("  k0 (LE uint64): 0x%016x\n", k0)
	fmt.Printf("  k1 (LE uint64): 0x%016x\n", k1)
	fmt.Println()

	drbg := NewHashDrbg(seed)

	const numBlocks = 5

	fmt.Printf("Generating %d blocks:\n\n", numBlocks)

	for i := 1; i <= numBlocks; i++ {
		block := drbg.NextBlock()

		// The length mask is the first 2 bytes of the block interpreted as
		// big-endian uint16, as used by the obfs4 framing layer.
		lengthMask := binary.BigEndian.Uint16(block[0:2])

		fmt.Printf("Block %d: %s\n", i, hex.EncodeToString(block[:]))
		fmt.Printf("  Length mask (BE uint16 of first 2 bytes): 0x%04x (%d)\n", lengthMask, lengthMask)
		fmt.Println()
	}
}
