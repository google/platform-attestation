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

package measurements

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	apb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"github.com/google/go-tpm/tpm2"
)

const (
	warmResetHandle uint32        = 0x01C10005
	warmResetSize                 = 8 // Stored as uint64_t.
	warmResetOffset uint16        = 0
	warmResetHash   tpm2.TPMAlgID = tpm2.TPMAlgSHA256
)

// expectedNVAttributes defines the expected attributes for the warm reset NV
// index, which is of type Counter.
var expectedNVAttributes tpm2.TPMANV = tpm2.TPMANV{
	PPWrite:        false,
	OwnerWrite:     false,
	AuthWrite:      false,
	PolicyWrite:    false,
	NT:             tpm2.TPMNTCounter,
	PolicyDelete:   true,
	WriteLocked:    true,
	WriteAll:       false,
	WriteDefine:    true,
	WriteSTClear:   false,
	GlobalLock:     false,
	PPRead:         false,
	OwnerRead:      false,
	AuthRead:       true,
	PolicyRead:     false,
	NoDA:           true,
	Orderly:        false,
	ClearSTClear:   false,
	ReadLocked:     false,
	Written:        true,
	PlatformCreate: false,
	ReadSTClear:    false,
}

// VerifyWarmResetNVIndex verifies the provided warm reset NV certification.
func VerifyWarmResetNVIndex(certify *apb.TpmAuxiliaryAttestation_SignedNvCertify, nonce []byte, ak crypto.PublicKey) (int64, error) {
	if certify == nil {
		return -1, fmt.Errorf("NV certification is nil")
	}

	// Check signature.
	if err := verifySig(certify, ak); err != nil {
		return -1, fmt.Errorf("failed to verify NV signature: %v", err)
	}

	nv, err := extractCpuWarmResetNV(certify.GetTpmsAttest(), nonce)
	if err != nil {
		return -1, fmt.Errorf("failed to extract NV: %v", err)
	}

	expectedName, err := cpuWarmResetNvPublicName(certify.GetTpmsNvPublic())
	if err != nil {
		return -1, fmt.Errorf("failed to get NV public name: %v", err)
	}

	// Validate NV.
	if !bytes.Equal(nv.IndexName.Buffer, expectedName.Buffer) {
		return -1, fmt.Errorf("NV name %v does not match expected name %v", nv.IndexName.Buffer, expectedName.Buffer)
	}

	if nv.Offset != warmResetOffset {
		return -1, fmt.Errorf("NV offset %v does not match expected offset %v", nv.Offset, warmResetOffset)
	}

	if len(nv.NVContents.Buffer) != warmResetSize {
		return -1, fmt.Errorf("NV data length %v does not match expected length %v", len(nv.NVContents.Buffer), warmResetSize)
	}

	var warmResetCount int64
	if err := binary.Read(bytes.NewReader(nv.NVContents.Buffer), binary.BigEndian, &warmResetCount); err != nil {
		return -1, fmt.Errorf("failed to read warm reset count: %v", err)
	}

	return warmResetCount, nil
}

func cpuWarmResetNvPublicName(publicBytes []byte) (*tpm2.TPM2BName, error) {
	nvPublic, err := tpm2.Unmarshal[tpm2.TPMSNVPublic](publicBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NV public: %v", err)
	}

	if nvPublic.NVIndex != tpm2.TPMIRHNVIndex(warmResetHandle) {
		return nil, fmt.Errorf("NV index %v does not match expected index %v", nvPublic.NVIndex, warmResetHandle)
	}

	if nvPublic.NameAlg != warmResetHash {
		return nil, fmt.Errorf("NV name algorithm %v does not match expected name algorithm %v", nvPublic.NameAlg, warmResetHash)
	}

	if nvPublic.DataSize != warmResetSize {
		return nil, fmt.Errorf("NV data size %v does not match expected data size %v", nvPublic.DataSize, warmResetSize)
	}

	if !bytes.Equal(tpm2.Marshal(&nvPublic.Attributes), tpm2.Marshal(&expectedNVAttributes)) {
		return nil, fmt.Errorf("NV attributes %v does not match expected attributes %v", nvPublic.Attributes, expectedNVAttributes)
	}

	// Expect empty policy.
	if len(nvPublic.AuthPolicy.Buffer) != 0 {
		return nil, fmt.Errorf("NV auth policy is not empty: %v", nvPublic.AuthPolicy.Buffer)
	}

	return tpm2.NVName(nvPublic)
}

func extractCpuWarmResetNV(tpmsattest []byte, nonce []byte) (*tpm2.TPMSNVCertifyInfo, error) {
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](tpmsattest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation: %v", err)
	}

	// Validate TPMS_ATTEST.
	if attest.Type != tpm2.TPMSTAttestNV {
		return nil, fmt.Errorf("wrong CertifyNV attestation type: %v", attest.Type)
	}

	if attest.Magic != tpm2.TPMGeneratedValue {
		return nil, fmt.Errorf("wrong magic value: %v", attest.Magic)
	}

	if !bytes.Equal(attest.ExtraData.Buffer, nonce) {
		return nil, fmt.Errorf("extra data does not match nonce: got %v, want %v", attest.ExtraData.Buffer, nonce)
	}

	return attest.Attested.NV()
}

func verifySig(certify *apb.TpmAuxiliaryAttestation_SignedNvCertify, ak crypto.PublicKey) error {
	ecdsaKey, ok := ak.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid AK type %T, only ECDSA is supported", ak)
	}

	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](certify.GetTpmtSignature())
	if err != nil {
		return fmt.Errorf("failed to unmarshal signature: %v", err)
	}

	dsa, err := sig.Signature.ECDSA()
	if err != nil {
		return fmt.Errorf("failed to get ECDSA member: %v", err)
	}

	var digest []byte
	switch dsa.Hash {
	case tpm2.TPMAlgSHA256:
		hash := sha256.Sum256(certify.GetTpmsAttest())
		digest = hash[:]
	default:
		return fmt.Errorf("only SHA256 is supported, got %v", dsa.Hash)
	}

	r := big.NewInt(0).SetBytes(dsa.SignatureR.Buffer)
	s := big.NewInt(0).SetBytes(dsa.SignatureS.Buffer)

	if ok := ecdsa.Verify(ecdsaKey, digest, r, s); !ok {
		return fmt.Errorf("failed to verify ECDSA signature")
	}

	return nil
}
