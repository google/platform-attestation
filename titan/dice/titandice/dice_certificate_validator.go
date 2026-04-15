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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/google/go-tpm/tpm2"
)

// Validator contains the data necessary to validate DICE cert chains.
type Validator struct {
	// TrustedScribeCerts is the set of trusted scribe certificates that signed
	// the DeviceIDScribeCertificate and the DeviceIDCertificate.
	TrustedScribeCerts map[KeyID]ScribeCertificate

	// TrustedRWCodeSigningKeyInfos is the set of trusted RW code signing key infos.
	TrustedRWCodeSigningKeyInfos map[KeyInfo]bool
}

// NewValidator creates a new Validator
func NewValidator(invariants *ValidateScribeCertificateChainOptions) (*Validator, error) {
	if invariants == nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingValidateOpts, invariants)
	}

	scribeCerts := make(map[KeyID]ScribeCertificate)
	for _, cert := range invariants.ScribeCertificates {
		parsedCert, err := ParseScribeCertificate(cert)
		if err != nil {
			return nil, err
		}
		parsedKeyID := ComputeKeyIDECDSA(parsedCert.SubjectKey())
		scribeCerts[parsedKeyID] = parsedCert
	}

	rwCodeSigningKeyInfos := make(map[KeyInfo]bool)
	for _, key := range invariants.RwSigningKeyInfos {
		rwCodeSigningKeyInfos[KeyInfo(key)] = true
	}

	return &Validator{
		TrustedScribeCerts:           scribeCerts,
		TrustedRWCodeSigningKeyInfos: rwCodeSigningKeyInfos,
	}, nil
}

// Fields which should have constant values in certificate headers.
const (
	headerPubKeySize     uint32 = 64  // sizeof(ECP256PublicKey)
	headerSignedDataSize uint32 = 128 // sizeof(DeviceIDCertificateHeader) + sizeof(ECP256PublicKey)
)

var (
	headerReserved0 []byte = []byte{0x00, 0x00}
	headerReserved1 []byte = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

type titanIdentifier interface {
	KeyID | KeyInfo
}

// sortedHexMapKeys returns a sorted list of the keys of the given map,
// formatted as hex strings.
// While sorting the list isn't crucial to returning helpful errors, it does
// make the list easier to scan through (especially for large lists).
func sortedHexMapKeys[K titanIdentifier, V any, M map[K]V](m M) []string {
	strings := make([]string, 0, len(m))
	for key := range m {
		strings = append(strings, fmt.Sprintf("0x%0x", key))
	}
	sort.Strings(strings)
	return strings
}

// compareHeaderUint16 compares two uint16 values and returns an error if they are not equal.
func compareHeaderUint16(want, got uint16, err error) error {
	if uint16(want) != got {
		return fmt.Errorf("%w: got %v, want %v (%v)", err, got, want, uint16(want))
	}
	return nil
}

// compareHeaderUint32 compares two uint32 values and returns an error if they are not equal. This
// function is templated because proto types don't support smaller sizes, whereas the corresponding
// Go type is a smaller size.
func compareHeaderUint32[T ~uint8 | ~uint16 | ~uint32](want T, got uint32, err error) error {
	if uint32(want) != got {
		return fmt.Errorf("%w: got %v, want %v (%v)", err, got, want, uint32(want))
	}
	return nil
}

// compareHeaderUint64 compares two uint64 values and returns an error if they are not equal.
func compareHeaderUint64(want, got uint64, err error) error {
	if uint64(want) != got {
		return fmt.Errorf("%w: got %v, want %v (%v)", err, got, want, uint64(want))
	}
	return nil
}

// compareHeaderBytes compares two []byte values and returns an error if they are not equal.
func compareHeaderBytes(want, got []byte, err error) error {
	if !bytes.Equal(want, got) {
		return fmt.Errorf("%w: got %v, want %v", err, got, want)
	}
	return nil
}

// serializeAliasKeyCertificate serializes an AliasKeyCertificate to a []byte message for
// signature validation. This is needed because the Signature Extension fields are optional,
// so they are appended for computing the hash.
func serializeAliasKeyCertificate(akc *AliasKeyCertificate) ([]byte, error) {
	if akc == nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingAKC, akc)
	}

	eht := akc.Header.ExtensionHeaderType
	if eht != SigExtensionHeaderTypeFirmwareHash && eht != SigExtensionHeaderTypeNone {
		return nil, fmt.Errorf("%w: %v", ErrAKCExtensionHeaderType, eht)
	}

	var msg bytes.Buffer

	binary.Write(&msg, binary.LittleEndian, akc.Header)
	binary.Write(&msg, binary.LittleEndian, akc.PublicKey)

	if akc.Header.ExtensionHeaderType == SigExtensionHeaderTypeFirmwareHash {
		binary.Write(&msg, binary.LittleEndian, akc.FWHash)
	}

	return msg.Bytes(), nil
}

// validateAliasKeyCertificate verifies the AliasKeyCertificate in a Titan DICE cert chain.
func validateAliasKeyCertificate(akc *AliasKeyCertificate, didc *DeviceIDCertificate, rwkis map[KeyInfo]bool) error {
	if akc == nil {
		return fmt.Errorf("%w: %v", ErrMissingAKC, akc)
	}
	if didc == nil {
		return fmt.Errorf("%w: %v", ErrMissingDIDC, didc)
	}

	header := akc.Header

	// Header constants
	if err := compareHeaderUint32(SigHeaderversion1, uint32(header.SignatureVersion), ErrAKCSignatureVersion); err != nil {
		return err
	}
	if err := compareHeaderUint32(SigAliasKeyCert, uint32(header.SignaturePurpose), ErrAKCSignaturePurpose); err != nil {
		return err
	}
	if err := compareHeaderUint32(KeyTypeAliasKey, uint32(header.KeyType), ErrAKCKeyType); err != nil {
		return err
	}
	if err := compareHeaderUint32(KeyOpSign, uint32(header.KeyOp), ErrAKCKeyOp); err != nil {
		return err
	}
	if err := compareHeaderUint32(KeyAlgECDSAP256, uint32(header.KeyAlg), ErrAKCKeyAlg); err != nil {
		return err
	}
	if err := compareHeaderBytes(headerReserved0, header.Reserved0[:], ErrAKCReserved0); err != nil {
		return err
	}
	if err := compareHeaderUint32(headerPubKeySize, uint32(header.PubKeySize), ErrAKCPubKeySize); err != nil {
		return err
	}
	if err := compareHeaderBytes(headerReserved1, header.Reserved1[:], ErrAKCReserved1); err != nil {
		return err
	}

	// Extension header type
	wantEHT := SigExtensionHeaderTypeNone
	// There is a small (1/ 2^256) chance that the firmware hash is all zeroes,
	// but this is highly unlikely.
	initializedHash := false
	for _, val := range akc.FWHash {
		if val != 0 {
			initializedHash = true
			break
		}
	}
	if initializedHash {
		wantEHT = SigExtensionHeaderTypeFirmwareHash
	}
	if err := compareHeaderUint32(wantEHT, uint32(header.ExtensionHeaderType), ErrAKCExtensionHeaderType); err != nil {
		return err
	}

	// RW signing key
	_, ok := rwkis[KeyInfo(header.CertValidity[0:4])]
	if !ok {
		return fmt.Errorf("%w: got 0x%0x, want one of %v", ErrAKCCertValidity, header.CertValidity[0:4], sortedHexMapKeys(rwkis))
	}

	// Device ID certificate similarity
	if err := compareHeaderUint64(didc.Header.HWID, akc.Header.HWID, ErrAKCHWID); err != nil {
		// If the Device ID certificate HWID is 0, then there's possible flash corruption.
		if didc.Header.HWID == 0 {
			return fmt.Errorf("%w. Alias Key Certificate hardware ID is %d", ErrDIDCHWID0, akc.Header.HWID)
		}
		return err
	}
	if err := compareHeaderUint16(didc.Header.HWCat, akc.Header.HWCat, ErrAKCHWCat); err != nil {
		return err
	}
	if err := compareHeaderUint32(didc.Header.BootloaderTag, akc.Header.BootloaderTag, ErrAKCBootloaderTag); err != nil {
		return err
	}

	// Device ID key info
	wantKeyInfo := ComputeKeyInfoTitan(didc.Key)
	if err := compareHeaderBytes(wantKeyInfo[:], akc.Header.KeyInfo[:], ErrAKCKeyInfo); err != nil {
		return err
	}

	// Signature Validation
	akMsg, err := serializeAliasKeyCertificate(akc)
	if err != nil {
		return err
	}
	if !VerifyECDSATitan(ECDSAPublicKey(didc.Key), akMsg, akc.Signature) {
		return ErrAKCSignature
	}

	return nil
}

// serializeDeviceIDCertificate serializes a DeviceIDCertificate to a []byte message for
// signature validation.
func serializeDeviceIDCertificate(didc *DeviceIDCertificate) ([]byte, error) {
	if didc == nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingDIDC, didc)
	}

	var msg bytes.Buffer
	binary.Write(&msg, binary.LittleEndian, didc.Header)
	binary.Write(&msg, binary.LittleEndian, didc.Key)
	return msg.Bytes(), nil
}

// validateDeviceIDCertificate verifies the DeviceIDCertificate in a Titan DICE cert chain.
func validateDeviceIDCertificate(didc *DeviceIDCertificate, scribecerts map[KeyID]ScribeCertificate) error {
	if didc == nil {
		return fmt.Errorf("%w: %v", ErrMissingDIDC, didc)
	}

	header := didc.Header

	// Header constants
	if err := compareHeaderUint32(SigHeaderversion1, uint32(header.SignatureVersion), ErrDIDCSignatureVersion); err != nil {
		return err
	}
	if err := compareHeaderUint32(SigDeviceIDCert, uint32(header.SignaturePurpose), ErrDIDCSignaturePurpose); err != nil {
		return err
	}
	if err := compareHeaderUint32(KeyTypeDeviceID, uint32(header.KeyType), ErrDIDCKeyType); err != nil {
		return err
	}
	if err := compareHeaderUint32(KeyOpSign, uint32(header.KeyOp), ErrDIDCKeyOp); err != nil {
		return err
	}
	if err := compareHeaderUint32(KeyAlgECDSAP256, uint32(header.KeyAlg), ErrDIDCKeyAlg); err != nil {
		return err
	}
	if err := compareHeaderUint32(SigExtensionHeaderTypeNone, uint32(header.ExtensionHeaderType), ErrDIDCExtensionHeaderType); err != nil {
		return err
	}
	if err := compareHeaderUint32(headerSignedDataSize, uint32(header.SignedDataSize), ErrDIDCSignedDataSize); err != nil {
		return err
	}

	// Find matching scribe certificate.
	matchedCert, ok := scribecerts[KeyID(header.ScribeKeyID)]
	if !ok {
		return fmt.Errorf("%w: got 0x%0x, want one of %v", ErrDIDCScribeKeyID, header.ScribeKeyID, sortedHexMapKeys(scribecerts))
	}

	// Validate matched scribe certificate.
	if err := compareHeaderBytes(header.ScribeKeyID[0:4], header.KeyInfo[:], ErrDIDCScribeKeyInfo); err != nil {
		return err
	}
	if err := compareHeaderUint16(SelfSignedScribeCertificateMagic, matchedCert.Type(), ErrDIDCScribeType); err != nil {
		return err
	}

	// Signature Validation
	didMsg, err := serializeDeviceIDCertificate(didc)
	if err != nil {
		return err
	}
	if !VerifyECDSATitan(matchedCert.SubjectKey(), didMsg, didc.Signature) {
		return ErrDIDCSignature
	}

	return nil
}

// serializeDeviceIDScribeCertificate serializes a DeviceIDCertificate to a []byte message
// for signature validation.
func serializeDeviceIDScribeCertificate(didsc *DeviceIDScribeCertificate) ([]byte, error) {
	if didsc == nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingDIDSC, didsc)
	}

	var msg bytes.Buffer

	binary.Write(&msg, binary.LittleEndian, didsc.DeviceIDCertHash)
	binary.Write(&msg, binary.LittleEndian, didsc.ScribeRWKey)

	return msg.Bytes(), nil
}

// validateDeviceIDScribeCertificate verifies the DeviceIDScribeCertificate in a Titan DICE cert
// chain.
func validateDeviceIDScribeCertificate(didsc *DeviceIDScribeCertificate, didc *DeviceIDCertificate, scribecerts map[KeyID]ScribeCertificate) error {
	if didsc == nil {
		return fmt.Errorf("%w: %v", ErrMissingDIDSC, didsc)
	}
	if didc == nil {
		return fmt.Errorf("%w: %v", ErrMissingDIDC, didc)
	}

	// Ensure hash matches DeviceIDCertificate
	didcMsg, err := serializeDeviceIDCertificate(didc)
	if err != nil {
		return err
	}
	h := sha256.New()
	h.Write(didcMsg)
	didcHash := h.Sum(nil)
	if !bytes.Equal(didcHash, didsc.DeviceIDCertHash[:]) {
		return fmt.Errorf("%w: got %v, want %v", ErrDIDSCCertHash, didsc.DeviceIDCertHash, didcHash)
	}

	// Find matching scribe certificate
	didscKeyID := ComputeKeyIDECDSA(p256KeyFromLEBytes(didsc.ScribeRWKey.QAX[:], didsc.ScribeRWKey.QAY[:]))
	matchedCert, ok := scribecerts[didscKeyID]
	if !ok {
		return fmt.Errorf("%w: got 0x%0x, want one of %v", ErrDIDSCScribeKey, didscKeyID, sortedHexMapKeys(scribecerts))
	}

	// Validate matched scribe certificate
	if err := compareHeaderUint16(TitanScribeCertificateMagic, matchedCert.Type(), ErrDIDSCScribeType); err != nil {
		return err
	}

	// Signature Validation
	didscMsg, err := serializeDeviceIDScribeCertificate(didsc)
	if err != nil {
		return err
	}
	if !VerifyECDSATitan(matchedCert.SubjectKey(), didscMsg, didsc.Signature) {
		return ErrDIDSCSignature
	}

	return nil
}

// ValidateScribeCertificateChain validates a Titan certificate chain rooted in a Scribe
// signature. This chain is used on Titan chips.
func ValidateScribeCertificateChain(certChain *TitanDiceScribeCertificateChain, validator *Validator) error {
	if certChain == nil {
		return ErrMissingCertChain
	}

	err := validateAliasKeyCertificate(&certChain.AliasKeyCertificate, &certChain.DeviceIDCertificate, validator.TrustedRWCodeSigningKeyInfos)
	if err != nil {
		return err
	}

	err = validateDeviceIDCertificate(&certChain.DeviceIDCertificate, validator.TrustedScribeCerts)
	if err != nil {
		return err
	}

	err = validateDeviceIDScribeCertificate(&certChain.DeviceIDScribeCertificate, &certChain.DeviceIDCertificate, validator.TrustedScribeCerts)
	if err != nil {
		return err
	}

	return nil
}

// verifyEKQualifiedName checks that the EK certificate's header qualified
// name matches one generated by the expected template.
func verifyEKQualifiedName(ekc *EKCertificate, expected_template *tpm2.TPMTPublic, expectFirmwareLimited bool) error {
	hierarchy := tpm2.TPMRHEndorsement
	if expectFirmwareLimited {
		hierarchy = tpm2.TPMRHFWEndorsement
	}
	qualifiedName, err := computePrimaryQualifiedName(&hierarchy, expected_template)
	if err != nil {
		return err
	}
	if ekc.Header.QualifiedName != [32]byte(qualifiedName) {
		return fmt.Errorf("%w: got %x, want %x", ErrEKTemplate, ekc.Header.QualifiedName, qualifiedName)
	}
	return nil
}

// serializeEKCertificate serializes an EK Certificate to a []byte message for
// signature validation.
func serializeEKCertificate(ekc *EKCertificate) ([]byte, error) {
	if ekc == nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingEKC, ekc)
	}

	var msg bytes.Buffer
	binary.Write(&msg, binary.LittleEndian, ekc.Header)
	binary.Write(&msg, binary.LittleEndian, ekc.PublicKey)
	return msg.Bytes(), nil
}

// ValidateEKCertificate validates an EK certificate signed by an alias key,
// returning the EK pub.
func ValidateEKCertificate(ekc *EKCertificate, akc *AliasKeyCertificate, expectFirmwareLimited bool) (*tpm2.TPMTPublic, error) {
	if ekc == nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingEKC, ekc)
	}
	if akc == nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingAKC, akc)
	}

	ekcHeader := ekc.Header.Header

	// Header constants
	if err := compareHeaderUint32(SigHeaderversion1, uint32(ekcHeader.SignatureVersion), ErrEKSignatureVersion); err != nil {
		return nil, err
	}
	if err := compareHeaderUint32(SigArchKeyCert, uint32(ekcHeader.SignaturePurpose), ErrEKSignaturePurpose); err != nil {
		return nil, err
	}
	if err := compareHeaderUint32(SigExtensionHeaderTypeNone, uint32(ekcHeader.ExtensionHeaderType), ErrEKExtensionHeaderType); err != nil {
		return nil, err
	}
	if err := compareHeaderUint32(KeyTypeTPMEK, uint32(ekcHeader.KeyType), ErrEKKeyType); err != nil {
		return nil, err
	}
	if err := compareHeaderUint32(KeyOpSign, uint32(ekcHeader.KeyOp), ErrEKKeyOp); err != nil {
		return nil, err
	}
	if err := compareHeaderUint32(KeyAlgECDSAP256, uint32(ekcHeader.KeyAlg), ErrEKKeyAlg); err != nil {
		return nil, err
	}
	if err := compareHeaderBytes(headerReserved0, ekcHeader.Reserved0[:], ErrEKReserved0); err != nil {
		return nil, err
	}
	if err := compareHeaderUint32(headerPubKeySize, uint32(ekcHeader.PubKeySize), ErrEKPubKeySize); err != nil {
		return nil, err
	}
	if err := compareHeaderBytes(headerReserved1, ekcHeader.Reserved1[:], ErrEKReserved1); err != nil {
		return nil, err
	}

	// Alias key certificate similarity
	if err := compareHeaderUint16(akc.Header.HWCat, ekcHeader.HWCat, ErrEKHWCat); err != nil {
		return nil, err
	}
	if err := compareHeaderUint64(akc.Header.HWID, ekcHeader.HWID, ErrEKHWID); err != nil {
		return nil, err
	}
	if err := compareHeaderUint32(akc.Header.BootloaderTag, ekcHeader.BootloaderTag, ErrEKBootloaderTag); err != nil {
		return nil, err
	}
	if err := compareHeaderUint32(akc.Header.FWEpoch, ekcHeader.FWEpoch, ErrEKFirmwareEpoch); err != nil {
		return nil, err
	}

	// Signature Validation
	ekMsg, err := serializeEKCertificate(ekc)
	if err != nil {
		return nil, err
	}
	if !VerifyECDSATitan(ECDSAPublicKey(akc.PublicKey), ekMsg, ekc.Signature) {
		return nil, ErrEKSignature
	}

	var expectedTemplate *tpm2.TPMTPublic
	if expectFirmwareLimited {
		if err := compareHeaderUint16(akc.Header.FWMajorVersion, ekcHeader.FWMajorVersion, ErrEKFirmwareMajorVersionMismatch); err != nil {
			return nil, err
		}
		expectedTemplate = titanFEKTemplate()
	} else {
		if err := compareHeaderUint16(0, ekcHeader.FWMajorVersion, ErrEKFirmwareMajorVersionNonZero); err != nil {
			return nil, err
		}
		expectedTemplate = titanEKTemplate()
	}

	// Insert the EK public key into the template.
	ekPub := ECDSAPublicKey(ekc.PublicKey)
	expectedTemplate.Unique = pubKeyToECCPublicID(ekPub)

	if err := verifyEKQualifiedName(ekc, expectedTemplate, expectFirmwareLimited); err != nil {
		return nil, err
	}

	return expectedTemplate, nil
}
