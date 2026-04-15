// Copyright 2026 Google LLC
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

package titandice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"slices"
)

func p256KeyFromLEBytes(x, y []byte) *ecdsa.PublicKey {
	xbig := make([]byte, len(x))
	copy(xbig, x)
	slices.Reverse(xbig)
	ybig := make([]byte, len(y))
	copy(ybig, y)
	slices.Reverse(ybig)

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xbig),
		Y:     new(big.Int).SetBytes(ybig),
	}
}

func signatureFromLEBytes(r, s []byte) (*big.Int, *big.Int) {
	rbig := make([]byte, len(r))
	copy(rbig, r)
	slices.Reverse(rbig)
	sbig := make([]byte, len(s))
	copy(sbig, s)
	slices.Reverse(sbig)

	return new(big.Int).SetBytes(rbig), new(big.Int).SetBytes(sbig)
}

// ComputeKeyIDECDSA computes a KeyID for an ECDSA public key.
// The KeyID is the first 16 bytes of the SHA256 hash of the little-endian
// representation of the public key's X and Y coordinates, concatenated.
func ComputeKeyIDECDSA(key *ecdsa.PublicKey) KeyID {
	h := sha256.New()
	xlittle := key.X.Bytes()
	slices.Reverse(xlittle)
	h.Write(xlittle)
	ylittle := key.Y.Bytes()
	slices.Reverse(ylittle)
	h.Write(ylittle)
	return KeyID(h.Sum(nil)[0:16])
}

// ECDSAPublicKey returns a stdlib ecdsa.PublicKey from a Titan-defined ECP256PublicKey.
func ECDSAPublicKey(key ECP256PublicKey) *ecdsa.PublicKey {
	return p256KeyFromLEBytes(key.QAX[:], key.QAY[:])
}

// ComputeKeyInfoTitan computes a 4-byte identifier for a Titan public key.
// It calculates the SHA-256 hash of the little-endian X and Y coordinates of the key,
// and returns the first 4 bytes of the digest.
func ComputeKeyInfoTitan(key ECP256PublicKey) KeyInfo {
	h := sha256.New()
	h.Write(key.QAX[:])
	h.Write(key.QAY[:])
	return KeyInfo(h.Sum(nil)[0:4])
}

// VerifyECDSATitan checks a Titan signature over the given data.
func VerifyECDSATitan(k *ecdsa.PublicKey, signedData []byte, sig ECP256Signature) bool {
	r, s := signatureFromLEBytes(sig.R[:], sig.S[:])
	digest := sha256.Sum256(signedData)

	return ecdsa.Verify(k, digest[:], r, s)
}
