package titandice

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"math/bits"
)

// Scribe certificates are structured data containing a Scribe-wielded key. These certificates
// serve as the trusted roots for DICE certificate chains used by Google Roots of Trust. The
// certificates themselves are usually self-signed; therefore the set of Scribe certificates
// must be carefully managed.
//
// This file contains functions for parsing structured data representing a Scribe certificate and
// accessing its fields.

// ScribeCertificate represents a common Scribe certificate.
type ScribeCertificate interface {
	// String implements the fmt.Stringer interface.
	String() string

	// Type returns the magic value of the Scribe certificate header, used to identify its type.
	Type() uint16

	// SubjectKey returns the public key used to verify Scribe signatures.
	SubjectKey() *ecdsa.PublicKey

	// AuthorityKey returns the public key used to sign the Scribe certificate.
	AuthorityKey() *ecdsa.PublicKey

	// Hash returns the hash of the Scribe certificate for signature verification.
	Hash() []byte

	// Print prints the Scribe certificate in a human-readable format
	Print()

	// Signature returns the signature on the Scribe certificate as a pair of big.Int values.
	Signature() (*big.Int, *big.Int)
}

const (
	// TitanScribeCertificateMagic is the magic value for a Scribe certificate used to sign Titan
	// payloads.
	TitanScribeCertificateMagic uint16 = 0x8230

	// SelfSignedScribeCertificateMagic is the magic value for a Scribe certificate used for
	// externally generated payload signing keys.
	SelfSignedScribeCertificateMagic uint16 = 0xf0ef
)

// All Scribe certificates share the following prefix structure.
type commonScribeCertificateHeader struct {
	Magic uint16 // LE. Equal to TitanScribeCertificateMagic
	Size  uint16 // BE. Size of the structure, excluding Magic and Size
}

// validateScribeCertificate ensures the ECDSA points and signature values are well-formed.
func validateScribeCertificate(sc ScribeCertificate) error {
	authKey := sc.AuthorityKey()
	if _, err := authKey.ECDH(); err != nil {
		return fmt.Errorf("ScribeCertificate.AuthorityKey() is not a valid EC point: %w", err)
	}

	subjectKey := sc.SubjectKey()
	if _, err := subjectKey.ECDH(); err != nil {
		return fmt.Errorf("ScribeCertificate.SubjectKey() is not a valid EC point: %w", err)
	}

	sigr, sigs := sc.Signature()
	zero := big.NewInt(0)
	n := authKey.Curve.Params().N

	// ensure r, s are in the range [1, n-1]
	if sigr.Cmp(zero) < 1 || sigr.Cmp(n) > -1 {
		return fmt.Errorf("ScribeCertificate.Signature() r is out of range [1, n-1]")
	}
	if sigs.Cmp(zero) < 1 || sigs.Cmp(n) > -1 {
		return fmt.Errorf("ScribeCertificate.Signature() s is out of range [1, n-1]")
	}

	return nil
}

// TitanScribeCertificate is a certificate over a scribe-RW key used to sign Titan payloads. The
// structure is mixed-endian, so each field's endianness is documented below.
type TitanScribeCertificate struct {
	Magic  uint16   // LE. Equal to TitanScribeCertificateMagic
	Size   uint16   // BE. Size of the structure, excluding Magic and Size
	DevID0 uint32   // LE. DEV_ID0 HW fuse; forms the chip's HWID
	DevID1 uint32   // LE. DEV_ID1 HW fuse; forms the chip's HWID
	RoRWR  [32]byte // LE. RWR register values, copied in order from HW
	RoX    [32]byte // LE. P256 x-coordinate of the public key used by RO
	RoY    [32]byte // LE. P256 y-coordinate of the public key used by RO
	RwHash [32]byte // LE. Hash of RW firmware
	RwFwr  [32]byte // LE. FWR register values, copied in order from HW
	RwX    [32]byte // LE. P256 x-coordinate of the public key used by RW
	RwY    [32]byte // LE. P256 y-coordinate of the public key used by RW
	SigR   [32]byte // LE. r-portion of the signature over the certificate
	SigS   [32]byte // LE. s-portion of the signature over the certificate
}

func (s *TitanScribeCertificate) String() string {
	return fmt.Sprintf("TitanScribeCertificate{DEVID: %x_%x}", s.DevID0, s.DevID1)
}

// Type implements the ScribeCertificate interface
func (s *TitanScribeCertificate) Type() uint16 { return TitanScribeCertificateMagic }

// SubjectKey implements the ScribeCertificate interface
func (s *TitanScribeCertificate) SubjectKey() *ecdsa.PublicKey {
	return p256KeyFromLEBytes(s.RwX[:], s.RwY[:])
}

// AuthorityKey implements the ScribeCertificate interface
func (s *TitanScribeCertificate) AuthorityKey() *ecdsa.PublicKey {
	return p256KeyFromLEBytes(s.RoX[:], s.RoY[:])
}

// Hash implements the ScribeCertificate interface
func (s *TitanScribeCertificate) Hash() []byte {
	h := sha256.New()
	binary.Write(h, binary.LittleEndian, s.Magic)
	binary.Write(h, binary.BigEndian, s.Size)
	binary.Write(h, binary.LittleEndian, s.DevID0)
	binary.Write(h, binary.LittleEndian, s.DevID1)
	binary.Write(h, binary.LittleEndian, s.RoRWR[:])
	binary.Write(h, binary.LittleEndian, s.RoX[:])
	binary.Write(h, binary.LittleEndian, s.RoY[:])
	binary.Write(h, binary.LittleEndian, s.RwHash[:])
	binary.Write(h, binary.LittleEndian, s.RwFwr[:])
	binary.Write(h, binary.LittleEndian, s.RwX[:])
	binary.Write(h, binary.LittleEndian, s.RwY[:])
	return h.Sum(nil)
}

// Print implements the ScribeCertificate interface
func (s *TitanScribeCertificate) Print() {
	fmt.Printf("Magic: 0x%x\n", s.Magic)
	fmt.Printf("Size: %d\n", s.Size)
	fmt.Printf("DevID0: 0x%x\n", s.DevID0)
	fmt.Printf("DevID1: 0x%x\n", s.DevID1)
	fmt.Printf("RoRWR: %x\n", s.RoRWR)
	fmt.Printf("RoX: %x\n", s.RoX)
	fmt.Printf("RoY: %x\n", s.RoY)
	fmt.Printf("RwHash: %x\n", s.RwHash)
	fmt.Printf("RwFwr: %x\n", s.RwFwr)
	fmt.Printf("RwX: %x\n", s.RwX)
	fmt.Printf("RwY: %x\n", s.RwY)
	fmt.Printf("SigR: %x\n", s.SigR)
	fmt.Printf("SigS: %x\n", s.SigS)
}

// Signature implements the ScribeCertificate interface
func (s *TitanScribeCertificate) Signature() (*big.Int, *big.Int) {
	return signatureFromLEBytes(s.SigR[:], s.SigS[:])
}

// SelfSignedScribeCertificate is a certificate over a scribe-held key used for external payload
// signing keys.
type SelfSignedScribeCertificate struct {
	Magic    uint16    // LE. Equal to TitanScribeCertificateMagic
	Size     uint16    // LE. Size of the structure, excluding Magic and Size
	Reserved [168]byte // Reserved bytes
	KeyX     [32]byte  // LE. P256 x-coordinate of the external public key
	KeyY     [32]byte  // LE. P256 y-coordinate of the external public key
	SigR     [32]byte  // LE. r-portion of the signature over the certificate
	SigS     [32]byte  // LE. s-portion of the signature over the certificate
}

func (s *SelfSignedScribeCertificate) String() string {
	return fmt.Sprintf("SelfSignedScribeCertificate{}")
}

// Type implements the ScribeCertificate interface
func (s *SelfSignedScribeCertificate) Type() uint16 { return SelfSignedScribeCertificateMagic }

// SubjectKey implements the ScribeCertificate interface
func (s *SelfSignedScribeCertificate) SubjectKey() *ecdsa.PublicKey {
	return p256KeyFromLEBytes(s.KeyX[:], s.KeyY[:])
}

// AuthorityKey implements the ScribeCertificate interface
func (s *SelfSignedScribeCertificate) AuthorityKey() *ecdsa.PublicKey {
	return s.SubjectKey()
}

// Hash implements the ScribeCertificate interface
func (s *SelfSignedScribeCertificate) Hash() []byte {
	h := sha256.New()
	binary.Write(h, binary.LittleEndian, s.Magic)
	binary.Write(h, binary.LittleEndian, s.Size)
	binary.Write(h, binary.LittleEndian, s.Reserved[:])
	binary.Write(h, binary.LittleEndian, s.KeyX[:])
	binary.Write(h, binary.LittleEndian, s.KeyY[:])
	return h.Sum(nil)
}

// Print implements the ScribeCertificate interface
func (s *SelfSignedScribeCertificate) Print() {
	fmt.Printf("Magic: 0x%x\n", s.Magic)
	fmt.Printf("Size: %d\n", s.Size)
	fmt.Printf("Reserved: %x\n", s.Reserved)
	fmt.Printf("KeyX: %x\n", s.KeyX)
	fmt.Printf("KeyY: %x\n", s.KeyY)
	fmt.Printf("SigR: %x\n", s.SigR)
	fmt.Printf("SigS: %x\n", s.SigS)
}

// Signature implements the ScribeCertificate interface
func (s *SelfSignedScribeCertificate) Signature() (*big.Int, *big.Int) {
	return signatureFromLEBytes(s.SigR[:], s.SigS[:])
}

// ParseScribeCertificate parses a byte buffer into a ScribeCertificate.
func ParseScribeCertificate(cert []byte) (ScribeCertificate, error) {
	certReader := bytes.NewReader(cert)

	var scribeHeader commonScribeCertificateHeader
	if err := binary.Read(certReader, binary.LittleEndian, &scribeHeader); err != nil {
		return nil, err
	}
	if _, err := certReader.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	switch scribeHeader.Magic {
	case TitanScribeCertificateMagic:
		var titanScribeCertificate TitanScribeCertificate
		if err := binary.Read(certReader, binary.LittleEndian, &titanScribeCertificate); err != nil {
			return nil, err
		}
		// scribe certificate size field is big endian (while all other fields
		// are little endian). Byte swap size field.
		titanScribeCertificate.Size = bits.ReverseBytes16(titanScribeCertificate.Size)
		if err := validateScribeCertificate(&titanScribeCertificate); err != nil {
			return nil, err
		}
		return &titanScribeCertificate, nil
	case SelfSignedScribeCertificateMagic:
		var selfSignedScribeCertificate SelfSignedScribeCertificate
		if err := binary.Read(certReader, binary.LittleEndian, &selfSignedScribeCertificate); err != nil {
			return nil, err
		}
		if err := validateScribeCertificate(&selfSignedScribeCertificate); err != nil {
			return nil, err
		}
		return &selfSignedScribeCertificate, nil
	default:
		return nil, fmt.Errorf("unsupported scribe certificate magic: %v", scribeHeader.Magic)
	}
}
