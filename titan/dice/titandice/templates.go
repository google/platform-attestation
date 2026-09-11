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
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/google/go-tpm/tpm2"
)

const p256ByteSize = 32

func getHashConstruction(hashAlg tpm2.TPMAlgID) (hash.Hash, error) {
	switch hashAlg {
	case tpm2.TPMAlgSHA256:
		return sha256.New(), nil
	case tpm2.TPMAlgSHA384:
		return sha512.New384(), nil
	case tpm2.TPMAlgSHA512:
		return sha512.New(), nil
	}

	return nil, fmt.Errorf("invalid or unsupported hash algorithm: %v", hashAlg)
}

// Converts an EC P256 public key's coordinates to an ECC TPM PublicID.
func pubKeyToECCPublicID(key *ecdsa.PublicKey) tpm2.TPMUPublicID {
	return tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: key.X.FillBytes(make([]byte, 32)),
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: key.Y.FillBytes(make([]byte, 32)),
		},
	})
}

// computePrimaryQualifiedName computes the Qualified Name for a primary key.
// See TPM 2.0 Specification Part 1: Architecture, Section 16 - Names.
func computePrimaryQualifiedName(hierarchy *tpm2.TPMHandle, pubKey *tpm2.TPMTPublic) ([]byte, error) {
	hasher, err := getHashConstruction(pubKey.NameAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to get hash construction: %w", err)
	}

	hBuf := new(bytes.Buffer)
	if err := binary.Write(hBuf, binary.BigEndian, hierarchy); err != nil {
		return nil, fmt.Errorf("failed to write hierarchy handle: %w", err)
	}
	hasher.Write(hBuf.Bytes())

	// Compute and add Object Name
	objName, err := tpm2.ObjectName(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute object name: %w", err)
	}
	hasher.Write(objName.Buffer)

	return hasher.Sum(nil), nil
}

func fekAttributes() tpm2.TPMAObject {
	return tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		STClear:             true,
		SensitiveDataOrigin: true,
		Restricted:          true,
		SignEncrypt:         true,
		NoDA:                true,
		UserWithAuth:        true,
		FirmwareLimited:     true,
	}
}

func ekAttributes() tpm2.TPMAObject {
	return tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		Restricted:          true,
		SignEncrypt:         true,
		NoDA:                true,
		UserWithAuth:        true,
	}
}

// Titan Base Endorsement Key template. The template includes various parameters
// (`fekAttributes`) for how the key should be derived and used.
func baseTemplate() *tpm2.TPMTPublic {
	return &tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
	}
}

func titanEKTemplate() *tpm2.TPMTPublic {
	ekTemplate := baseTemplate()
	ekTemplate.ObjectAttributes = ekAttributes()
	return ekTemplate
}

func titanFEKTemplate() *tpm2.TPMTPublic {
	fekTemplate := baseTemplate()
	fekTemplate.ObjectAttributes = fekAttributes()
	return fekTemplate
}
