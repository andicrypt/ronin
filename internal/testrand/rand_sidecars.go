package testrand

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// RandFieldElement generates a field element
func RandFieldElement() [fr.Bytes]byte {
	bytes := make([]byte, fr.Bytes)
	prng.Read(bytes)

	var r fr.Element
	r.SetBytes(bytes)

	return gokzg4844.SerializeScalar(r)
}

// RandBlobSidecars generate a valid random blob sidecars
func RandBlobSidecars() (*kzg4844.Blob, *kzg4844.Commitment, *kzg4844.Proof) {
	var blob kzg4844.Blob
	for i := 0; i < len(blob); i += gokzg4844.SerializedScalarSize {
		fieldElementBytes := RandFieldElement()
		copy(blob[i:i+gokzg4844.SerializedScalarSize], fieldElementBytes[:])
	}
	commitment, err := kzg4844.BlobToCommitment(&blob)
	if err != nil {
		panic(err)
	}
	proof, err := kzg4844.ComputeBlobProof(&blob, commitment)
	if err != nil {
		panic(err)
	}
	return &blob, &commitment, &proof
}
