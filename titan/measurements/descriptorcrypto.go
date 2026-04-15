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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"strings"
)

/* Signature of the hash of the image_descriptor structure up to and excluding
* this struct (optional).
 */

// SignatureMagicLE magic number identifying any of the Signature* structs.
var SignatureMagicLE = binary.LittleEndian.Uint32([]byte("SIGN"))

// RSA2048PKCS1_5 signature and modulus sizes.
const (
	RSA2048PKCS1_5ModulusNbytes   = 256
	RSA2048PKCS1_5SignatureNbytes = 256
)

// SignatureRSA2048PKCS1_5 signature and parameters used to sign.
type SignatureRSA2048PKCS1_5 struct {
	SignatureMagic uint32 // 0x4e474953 (LE) = "SIGN"
	// Monotonic index of the key used to sign the image (starts at 1).
	KeyIndex uint16
	// Used to revoke keys, persisted by the enforcer.
	MinKeyIndex uint16
	Exponent    uint32                               // little-endian
	Modulus     [RSA2048PKCS1_5ModulusNbytes]uint8   // big-endian
	Signature   [RSA2048PKCS1_5SignatureNbytes]uint8 // big-endian
}

// Read deserializes a SignatureRSA2048PKCS1_5 from a binary image descriptor.
func (s *SignatureRSA2048PKCS1_5) Read(r io.Reader) error {
	// Read one field at a time; this allows partially populated structures to be read.
	err := binary.Read(r, binary.LittleEndian, &s.SignatureMagic)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.KeyIndex)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.MinKeyIndex)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Exponent)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Modulus)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Signature)
	if err != nil {
		return nil
	}
	if s.SignatureMagic != SignatureMagicLE {
		// optional signature does not exist, an error at the caller,
		// not here.
		return nil
	}
	return nil
}

// String representation of SignatureRSA2048PKCS1_5 structure.
func (s *SignatureRSA2048PKCS1_5) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SignatureRSA2048PKCS1_5{\n")
	fmt.Fprintf(&b, "  SignatureMagic: 0x%08x\n", s.SignatureMagic)
	fmt.Fprintf(&b, "  KeyIndex: 0x%04x\n", s.KeyIndex)
	fmt.Fprintf(&b, "  MinKeyIndex: 0x%04x\n", s.MinKeyIndex)
	fmt.Fprintf(&b, "  Exponent: 0x%08x\n", s.Exponent)
	fmt.Fprintf(&b, "  Signature: %v\n", s.Signature[:])
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// SignatureValue returns the raw bytes of the signature.
func (s *SignatureRSA2048PKCS1_5) SignatureValue() []byte {
	return s.Signature[:]
}

// setModulus sets the raw public key bytes.
func (s *SignatureRSA2048PKCS1_5) setModulus(b []byte) error {
	if n := copy(s.Modulus[:], b); n != len(s.Modulus) || n != len(b) {
		return fmt.Errorf("invalid Modulus length: %d", len(b))
	}
	return nil
}

// ModulusValue return the raw public key bytes.
func (s *SignatureRSA2048PKCS1_5) ModulusValue() []byte {
	return s.Modulus[:]
}

// ExponentValue return the public key exponent.
func (s *SignatureRSA2048PKCS1_5) ExponentValue() uint32 {
	return s.Exponent
}

// SetSignature sets the raw signature bytes.
func (s *SignatureRSA2048PKCS1_5) SetSignature(b []byte) error {
	if n := copy(s.Signature[:], b); n != len(s.Signature) || n != len(b) {
		return fmt.Errorf("invalid signature length: %d", len(b))
	}
	return nil
}

// RSA3072PKCS1_5 signature and modulus sizes.
const (
	RSA3072PKCS1_5ModulusNbytes   = 384
	RSA3072PKCS1_5SignatureNbytes = 384
)

// SignatureRSA3072PKCS1_5 signature and parameters used to sign.
type SignatureRSA3072PKCS1_5 struct {
	SignatureMagic uint32 // 0x4e474953 (LE)
	// Monotonic index of the key used to sign the image (starts at 1).
	KeyIndex uint16
	// Used to revoke keys, persisted by the enforcer.
	MinKeyIndex uint16
	Exponent    uint32                               // little-endian
	Modulus     [RSA3072PKCS1_5ModulusNbytes]uint8   // big-endian
	Signature   [RSA3072PKCS1_5SignatureNbytes]uint8 // big-endian
}

// Read deserializes a SignatureRSA3072PKCS1_5 from a binary image descriptor.
func (s *SignatureRSA3072PKCS1_5) Read(r io.Reader) error {
	// Read one field at a time; this allows partially populated structures to be read.
	err := binary.Read(r, binary.LittleEndian, &s.SignatureMagic)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.KeyIndex)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.MinKeyIndex)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Exponent)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Modulus)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Signature)
	if err != nil {
		return nil
	}
	if s.SignatureMagic != SignatureMagicLE {
		// optional signature does not exist, an error at the caller,
		// not here.
		return nil
	}
	return nil
}

// String representation of SignatureRSA3072PKCS1_5 structure.
func (s *SignatureRSA3072PKCS1_5) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SignatureRSA3072PKCS1_5{\n")
	fmt.Fprintf(&b, "  SignatureMagic: 0x%08x\n", s.SignatureMagic)
	fmt.Fprintf(&b, "  KeyIndex: 0x%04x\n", s.KeyIndex)
	fmt.Fprintf(&b, "  MinKeyIndex: 0x%04x\n", s.MinKeyIndex)
	fmt.Fprintf(&b, "  Exponent: 0x%08x\n", s.Exponent)
	fmt.Fprintf(&b, "  Signature: %v\n", s.Signature[:])
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// SignatureValue returns the raw bytes of the signature.
func (s *SignatureRSA3072PKCS1_5) SignatureValue() []byte {
	return s.Signature[:]
}

// setModulus sets the raw public key bytes.
func (s *SignatureRSA3072PKCS1_5) setModulus(b []byte) error {
	if n := copy(s.Modulus[:], b); n != len(s.Modulus) || n != len(b) {
		return fmt.Errorf("invalid Modulus length: %d", len(b))
	}
	return nil
}

// ModulusValue return the raw public key bytes.
func (s *SignatureRSA3072PKCS1_5) ModulusValue() []byte {
	return s.Modulus[:]
}

// ExponentValue return the public key exponent.
func (s *SignatureRSA3072PKCS1_5) ExponentValue() uint32 {
	return s.Exponent
}

// SetSignature sets the raw signature bytes.
func (s *SignatureRSA3072PKCS1_5) SetSignature(b []byte) error {
	if n := copy(s.Signature[:], b); n != len(s.Signature) || n != len(b) {
		return fmt.Errorf("invalid signature length: %d", len(b))
	}
	return nil
}

// RSA4096PKCS1_5 signature and modulus sizes.
const (
	RSA4096PKCS1_5ModulusNbytes        = 512
	RSA4096PKCS1_5SignatureNbytes      = 512
	RSA4096PKCS15SHA512ModulusNbytes   = 512
	RSA4096PKCS15SHA512SignatureNbytes = 512
)

// SignatureRSA4096PKCS1_5 signature and parameters used to sign.
type SignatureRSA4096PKCS1_5 struct {
	SignatureMagic uint32 // 0x4e474953 (LE)
	// Monotonic index of the key used to sign the image (starts at 1).
	KeyIndex uint16
	// Used to revoke keys, persisted by the enforcer.
	MinKeyIndex uint16
	Exponent    uint32                               // little-endian
	Modulus     [RSA4096PKCS1_5ModulusNbytes]uint8   // big-endian
	Signature   [RSA4096PKCS1_5SignatureNbytes]uint8 // big-endian
}

// Read deserializes a SignatureRSA4096PKCS1_5 from a binary image descriptor.
func (s *SignatureRSA4096PKCS1_5) Read(r io.Reader) error {
	// Read one field at a time; this allows partially populated structures to be read.
	err := binary.Read(r, binary.LittleEndian, &s.SignatureMagic)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.KeyIndex)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.MinKeyIndex)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Exponent)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Modulus)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Signature)
	if err != nil {
		return nil
	}
	if s.SignatureMagic != SignatureMagicLE {
		// optional signature does not exist, an error at the caller,
		// not here.
		return nil
	}
	return nil
}

// String representation of SignatureRSA4096PKCS1_5 structure.
func (s *SignatureRSA4096PKCS1_5) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SignatureRSA4096PKCS1_5{\n")
	fmt.Fprintf(&b, "  SignatureMagic: 0x%08x\n", s.SignatureMagic)
	fmt.Fprintf(&b, "  KeyIndex: 0x%04x\n", s.KeyIndex)
	fmt.Fprintf(&b, "  MinKeyIndex: 0x%04x\n", s.MinKeyIndex)
	fmt.Fprintf(&b, "  Exponent: 0x%08x\n", s.Exponent)
	fmt.Fprintf(&b, "  Signature: %v\n", s.Signature[:])
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// SignatureValue returns the raw bytes of the signature.
func (s *SignatureRSA4096PKCS1_5) SignatureValue() []byte {
	return s.Signature[:]
}

// setModulus sets the raw public key bytes.
func (s *SignatureRSA4096PKCS1_5) setModulus(b []byte) error {
	if n := copy(s.Modulus[:], b); n != len(s.Modulus) || n != len(b) {
		return fmt.Errorf("invalid Modulus length: %d", len(b))
	}
	return nil
}

// ModulusValue return the raw public key bytes.
func (s *SignatureRSA4096PKCS1_5) ModulusValue() []byte {
	return s.Modulus[:]
}

// ExponentValue return the public key exponent.
func (s *SignatureRSA4096PKCS1_5) ExponentValue() uint32 {
	return s.Exponent
}

// SetSignature sets the raw signature bytes.
func (s *SignatureRSA4096PKCS1_5) SetSignature(b []byte) error {
	if n := copy(s.Signature[:], b); n != len(s.Signature) || n != len(b) {
		return fmt.Errorf("invalid signature length: %d", len(b))
	}
	return nil
}

// SignatureRSA4096PKCS15SHA512 signature and parameters used to sign.
// SignatureRSA4096PKCS15SHA512 SignatureRSA4096PKCS1_5 have the same layout.
// even though the signing algorithms differ in their use of hash functions.
type SignatureRSA4096PKCS15SHA512 struct {
	SignatureMagic uint32 // 0x4e474953 (LE)
	// Monotonic index of the key used to sign the image (starts at 1).
	KeyIndex uint16
	// Used to revoke keys, persisted by the enforcer.
	MinKeyIndex uint16
	Exponent    uint32                                    // little-endian
	Modulus     [RSA4096PKCS15SHA512ModulusNbytes]uint8   // big-endian
	Signature   [RSA4096PKCS15SHA512SignatureNbytes]uint8 // big-endian
}

// Read deserializes a SignatureRSA4096PKCS15SHA512 from a binary image descriptor.
func (s *SignatureRSA4096PKCS15SHA512) Read(r io.Reader) error {
	// Read one field at a time; this allows partially populated structures to be read.
	err := binary.Read(r, binary.LittleEndian, &s.SignatureMagic)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.KeyIndex)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.MinKeyIndex)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Exponent)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Modulus)
	if err != nil {
		return nil
	}
	err = binary.Read(r, binary.LittleEndian, &s.Signature)
	if err != nil {
		return nil
	}
	if s.SignatureMagic != SignatureMagicLE {
		// optional signature does not exist, an error at the caller,
		// not here.
		return nil
	}
	return nil
}

// String representation of SignatureRSA4096PKCS15SHA512 structure.
func (s *SignatureRSA4096PKCS15SHA512) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SignatureRSA4096PKCS15SHA512{\n")
	fmt.Fprintf(&b, "  SignatureMagic: 0x%08x\n", s.SignatureMagic)
	fmt.Fprintf(&b, "  KeyIndex: 0x%04x\n", s.KeyIndex)
	fmt.Fprintf(&b, "  MinKeyIndex: 0x%04x\n", s.MinKeyIndex)
	fmt.Fprintf(&b, "  Exponent: 0x%08x\n", s.Exponent)
	fmt.Fprintf(&b, "  Signature: %v\n", s.Signature[:])
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// SignatureValue returns the raw bytes of the signature.
func (s *SignatureRSA4096PKCS15SHA512) SignatureValue() []byte {
	return s.Signature[:]
}

// setModulus sets the raw public key bytes.
func (s *SignatureRSA4096PKCS15SHA512) setModulus(b []byte) error {
	if n := copy(s.Modulus[:], b); n != len(s.Modulus) || n != len(b) {
		return fmt.Errorf("invalid Modulus length: %d", len(b))
	}
	return nil
}

// ModulusValue return the raw public key bytes.
func (s *SignatureRSA4096PKCS15SHA512) ModulusValue() []byte {
	return s.Modulus[:]
}

// ExponentValue return the public key exponent.
func (s *SignatureRSA4096PKCS15SHA512) ExponentValue() uint32 {
	return s.Exponent
}

// SetSignature sets the raw signature bytes.
func (s *SignatureRSA4096PKCS15SHA512) SetSignature(b []byte) error {
	if n := copy(s.Signature[:], b); n != len(s.Signature) || n != len(b) {
		return fmt.Errorf("invalid signature length: %d", len(b))
	}
	return nil
}

// SHA256 digest and parameters used to sign.
type SHA256 struct {
	SignatureMagic uint32 // 0x4e474953 (LE)
	Digest         [sha256.Size]uint8
}

// String representation of SHA256 structure.
func (s *SHA256) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SHA256{\n")
	fmt.Fprintf(&b, "  SignatureMagic: 0x%08x\n", s.SignatureMagic)
	fmt.Fprintf(&b, "  Digest: %v\n", s.Digest[:])
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// Read deserializes a SHA256 from a binary image descriptor.
func (s *SHA256) Read(r io.Reader) error {
	err := binary.Read(r, binary.LittleEndian, s)
	if err != nil {
		return nil
	}
	if s.SignatureMagic != SignatureMagicLE {
		// optional signature does not exist, an error at the caller,
		// not here.
		return nil
	}
	return nil
}

// SignatureValue returns the raw bytes of the signature.
func (s *SHA256) SignatureValue() []byte {
	return s.Digest[:]
}

// setModulus sets the raw public key bytes.
func (s *SHA256) setModulus(b []byte) error {
	fmt.Errorf("unsupported method for signatures of type SHA256")
	return nil
}

// ModulusValue return the raw public key bytes.
func (s *SHA256) ModulusValue() []byte {
	fmt.Errorf("unsupported method for signatures of type SHA256")
	return nil
}

// ExponentValue return the public key exponent.
func (s *SHA256) ExponentValue() uint32 {
	fmt.Errorf("unsupported method for signatures of type SHA256")
	return 0
}

// SetSignature sets the raw signature bytes.
func (s *SHA256) SetSignature(b []byte) error {
	if n := copy(s.Digest[:], b); n != len(s.Digest) || n != len(b) {
		return fmt.Errorf("invalid signature length: %d", len(b))
	}
	return nil
}

// SignatureRSAOrDigest generalizes the handling of descriptor RSA-based signature and digest structures.
type SignatureRSAOrDigest interface {
	// Read the serialized version of the signature structure.
	Read(io.Reader) error
	// Access the raw bytes of the signature.
	SignatureValue() []byte
	// setModulus is a helper to set the raw bytes of the public key.
	setModulus([]byte) error
	// Modulus makes the raw bytes of the public key available.
	// Note that binary.* needs the underlying field to be exported. So Get*() here.
	ModulusValue() []byte
	// Expoenent makes the exponent of the public key available.
	// Note that binary.* needs the underlying field to be exported. So Get*() here.
	ExponentValue() uint32
	// SetSignature sets the raw bytes of the signature.
	SetSignature([]byte) error
}

// NewSignatureRSA returns a new concrete instance of the specified CR51 signature structure.
func NewSignatureRSA(scheme VerificationScheme, keyIndex, minKeyIndex uint16, exponent uint32, pubkey []byte) (SignatureRSAOrDigest, error) {
	var sig SignatureRSAOrDigest
	switch scheme {
	case VerificationSchemeRSA2048PKCS15SHA256:
		sig = &SignatureRSA2048PKCS1_5{
			SignatureMagic: SignatureMagicLE,
			KeyIndex:       keyIndex,
			MinKeyIndex:    minKeyIndex,
			Exponent:       exponent,
		}
	case VerificationSchemeRSA3072PKCS15SHA256:
		sig = &SignatureRSA3072PKCS1_5{
			SignatureMagic: SignatureMagicLE,
			KeyIndex:       keyIndex,
			MinKeyIndex:    minKeyIndex,
			Exponent:       exponent,
		}
	case VerificationSchemeRSA4096PKCS15SHA256:
		sig = &SignatureRSA4096PKCS1_5{
			SignatureMagic: SignatureMagicLE,
			KeyIndex:       keyIndex,
			MinKeyIndex:    minKeyIndex,
			Exponent:       exponent,
		}
	case VerificationSchemeRSA4096PKCS15SHA512:
		sig = &SignatureRSA4096PKCS15SHA512{
			SignatureMagic: SignatureMagicLE,
			KeyIndex:       keyIndex,
			MinKeyIndex:    minKeyIndex,
			Exponent:       exponent,
		}
	default:
		return nil, fmt.Errorf("unsupported signature scheme: %v", scheme)
	}
	if pubkey != nil {
		if err := sig.setModulus(pubkey); err != nil {
			return nil, err
		}
	}
	return sig, nil
}

// NewSignatureDigest returns a new concrete instance of the specified CR51 signature digest structure.
func NewSignatureDigest(scheme VerificationScheme) (SignatureRSAOrDigest, error) {
	var sig SignatureRSAOrDigest
	switch scheme {
	case VerificationSchemeSHA256:
		sig = &SHA256{
			SignatureMagic: SignatureMagicLE,
		}
	default:
		return nil, fmt.Errorf("unsupported signature scheme: %v", scheme)
	}

	return sig, nil
}

/* Hash the static regions (IMAGE_REGION_STATIC) excluding this descriptor
* structure i.e. skipping image_descriptor.descriptor_size bytes (optional).
 */

// HashMagicLE is the magic number ide tifier for a hash structure.
var HashMagicLE = binary.LittleEndian.Uint32([]byte("HASH"))

// DescriptorHash provides a generic interface for hash-algo specific implementations.
type DescriptorHash interface {
	String() string
	Type() HashType
	New() hash.Hash
	// Set the hash bytes that were read or will be written
	Set([]byte) error
	// Get the hash bytes that were read or will be written
	Bytes() []byte
	Magic() uint32
}

// NewDescriptorHash is a factory for HashSHA*{} based on the given type.
func NewDescriptorHash(ht HashType) (DescriptorHash, error) {
	switch ht {
	case HashTypeSHA2_256:
		return &HashSHA256{HashMagic: HashMagicLE}, nil
	case HashTypeSHA2_512:
		return &HashSHA512{HashMagic: HashMagicLE}, nil
	}
	return nil, fmt.Errorf("HashType %v is not implemented", ht)
}

// HashSHA256 record.
type HashSHA256 struct {
	// HashMagic must be set to HashMagicLE
	HashMagic uint32
	// Hash is the SHA256 hash output.
	Hash [sha256.Size]uint8
}

// String representation of HashSHA256.
func (h HashSHA256) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HashSHA256{\n")
	fmt.Fprintf(&b, "  HashMagic: 0x%08x\n", h.HashMagic)
	fmt.Fprintf(&b, "  Hash: %v\n", h.Hash[:])
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// Type returns the type of hash being implemented.
func (h HashSHA256) Type() HashType {
	return HashTypeSHA2_256
}

// New returns a new instance.
func (h HashSHA256) New() hash.Hash {
	return sha256.New()
}

// Set overwrites the value of Hash.
func (h *HashSHA256) Set(b []byte) error {
	if n := copy(h.Hash[:], b); n != len(h.Hash) || n != len(b) {
		return fmt.Errorf("invalid hash length")
	}
	return nil
}

// Bytes returns the stored hash value.
func (h HashSHA256) Bytes() []byte {
	return h.Hash[:]
}

// Magic returns the stored magic constant.
func (h HashSHA256) Magic() uint32 {
	return h.HashMagic
}

// Size of the stored hash value.
func (h HashSHA256) Size() int {
	return sha256.Size
}

// HashSHA512 record.
type HashSHA512 struct {
	// HashMagic must be set to HashMagicLE
	HashMagic uint32
	// Hash is the SHA512 hash output.
	Hash [sha512.Size]uint8
}

// String representation of HashSHA512.
func (h HashSHA512) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HashSHA512{\n")
	fmt.Fprintf(&b, "  HashMagic: 0x%08x\n", h.HashMagic)
	fmt.Fprintf(&b, "  Hash: %v\n", h.Hash[:])
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// Type returns the type of hash being implemented.
func (h HashSHA512) Type() HashType {
	return HashTypeSHA2_512
}

// New returns an instance of a HashSHA512 struct.
func (h HashSHA512) New() hash.Hash {
	return sha512.New()
}

// Set overwrites the value of Hash.
func (h *HashSHA512) Set(b []byte) error {
	if n := copy(h.Hash[:], b); n != len(h.Hash) || n != len(b) {
		return fmt.Errorf("invalid hash length")
	}
	return nil
}

// Bytes returns the stored hash value.
func (h HashSHA512) Bytes() []byte {
	return h.Hash[:]
}

// Magic returns the stored magic constant.
func (h HashSHA512) Magic() uint32 {
	return h.HashMagic
}

// Size of the stored hash value.
func (h HashSHA512) Size() int {
	return sha512.Size
}
