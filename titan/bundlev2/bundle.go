// Package bundlev2 provides access to Bundle Version 2 update bundle structures and logic.
package bundlev2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/google/platform-attestation/titan/titanheader"
)

// Titan SignedHeader magic values.
// Note: we jump from Titan V1 to V3, skipping V2 (0xfffffffe), as V2 never made it into
// production datacenters.
const (
	TitanV1Magic = 0xffffffff
	TitanV3Magic = 0xfffffffd
)

// UnsignedMetadataConstants:
const (
	AlignmentSize          = 2048
	UnsignedMetadataMagic  = 0x494d475f48415348 // "IMG_HASH"
	UnsignedMetadataLength = 64                 // combined length of target hashes
)

// UnsignedMetadata represents the trailing metadata block containing image hashes.
type UnsignedMetadata struct {
	Tag          uint64
	StructLength uint32
	RWAHash      [32]byte
	RWBHash      [32]byte
}

// TitanImageMetadataV2 holds the unified digest and version of a parsed Bundle Version 2 update bundle.
type TitanImageMetadataV2 struct {
	Digest []byte
	Major  uint32
}

// HashSingleFirmwareV2 parses a Titan firmware stream, validates its metadata, and returns its digest and version.
func HashSingleFirmwareV2(r io.ReadSeeker, copyStart int64) ([]byte, uint32, error) {
	if _, err := r.Seek(copyStart, io.SeekStart); err != nil {
		return nil, 0, fmt.Errorf("failed to seek to SignedHeader: %w", err)
	}

	var header [titanheader.SignedHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, 0, fmt.Errorf("failed to read SignedHeader: %w", err)
	}

	magic, err := readUint32(header[titanheader.MagicFieldOffset : titanheader.MagicFieldOffset+4])
	if err != nil {
		return nil, 0, err
	}
	// Accept Titan V1 or Titan V3 SignedHeader magic values.
	if magic != TitanV1Magic && magic != TitanV3Magic {
		return nil, 0, fmt.Errorf("invalid SignedHeader magic 0x%x", magic)
	}

	imageSize, err := readUint32(header[titanheader.ImageSizeFieldOffset : titanheader.ImageSizeFieldOffset+4])
	if err != nil {
		return nil, 0, err
	}
	major, err := readUint32(header[titanheader.MajorFieldOffset : titanheader.MajorFieldOffset+4])
	if err != nil {
		return nil, 0, err
	}

	// Read signed program body starting at tag field (offset 392) to imageSize
	bodySize := imageSize - titanheader.TagFieldOffset
	if _, err := r.Seek(copyStart+titanheader.TagFieldOffset, io.SeekStart); err != nil {
		return nil, 0, fmt.Errorf("failed to seek to program body start: %w", err)
	}

	programBody := make([]byte, bodySize)
	if _, err := io.ReadFull(r, programBody); err != nil {
		return nil, 0, fmt.Errorf("failed to read program body: %w", err)
	}

	calculatedHash := sha256.Sum256(programBody)

	// The UnsignedMetadata trailer lies at the next 2KB flash boundary (alignUp)
	alignedStart := alignUp(imageSize, AlignmentSize)
	if _, err := r.Seek(copyStart+int64(alignedStart), io.SeekStart); err != nil {
		return nil, 0, fmt.Errorf("failed to seek to unsigned metadata: %w", err)
	}

	var metadata UnsignedMetadata
	if err := binary.Read(r, binary.LittleEndian, &metadata); err != nil {
		return nil, 0, fmt.Errorf("failed to read UnsignedMetadata: %w", err)
	}

	// Validate the metadata header signature and length logic
	if metadata.Tag != UnsignedMetadataMagic {
		return nil, 0, fmt.Errorf("unexpected metadata magic 0x%x", metadata.Tag)
	}
	if metadata.StructLength != UnsignedMetadataLength {
		return nil, 0, fmt.Errorf("unexpected metadata structural length %d", metadata.StructLength)
	}

	// Verify calculatedHash matches either metadata.RWAHash or metadata.RWBHash (cross-copy attestation)
	matchA := bytes.Equal(calculatedHash[:], metadata.RWAHash[:])
	matchB := bytes.Equal(calculatedHash[:], metadata.RWBHash[:])
	if !matchA && !matchB {
		return nil, 0, fmt.Errorf("cryptographic verification failed: calculated hash %x does not match metadata RWAHash (%x) nor RWBHash (%x)", calculatedHash, metadata.RWAHash, metadata.RWBHash)
	}

	return calculatedHash[:], major, nil
}

// HashBundleV2 parses a Bundle Version 2 update bundle and returns its unified digest and version.
func HashBundleV2(r io.ReadSeeker) (*TitanImageMetadataV2, error) {
	offset, err := titanheader.ScanHeader(r)
	if err != nil {
		return nil, fmt.Errorf("HashBundleV2 failed: %w", err)
	}

	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("HashBundleV2 failed to seek to descriptor: %w", err)
	}

	var desc titanheader.TitanRegionDescriptor
	if err := binary.Read(r, binary.LittleEndian, &desc); err != nil {
		return nil, fmt.Errorf("HashBundleV2 failed to read RegionDescriptor: %w", err)
	}

	if desc.DescriptorMagic != titanheader.TitanHeaderMagic {
		return nil, fmt.Errorf("HashBundleV2 failed: unexpected descriptor magic 0x%x", desc.DescriptorMagic)
	}

	// 1. Image A measurement and verification
	firmwareAOffset := offset + int64(desc.AppFirmwareAOffset)
	digestA, majorA, err := HashSingleFirmwareV2(r, firmwareAOffset)
	if err != nil {
		return nil, fmt.Errorf("HashBundleV2: image A failed: %w", err)
	}

	// 2. Image B measurement and verification
	firmwareBOffset := offset + int64(desc.AppFirmwareBOffset)
	digestB, majorB, err := HashSingleFirmwareV2(r, firmwareBOffset)
	if err != nil {
		return nil, fmt.Errorf("HashBundleV2: image B failed: %w", err)
	}

	// 3. Verify version symmetry across slots
	if majorA != majorB {
		return nil, fmt.Errorf("HashBundleV2 failed: firmware image A major version (%d) does not match image B major version (%d)", majorA, majorB)
	}

	// 4. Concatenate the two copy hashes and calculate the unified digest
	var concat [64]byte
	copy(concat[0:32], digestA)
	copy(concat[32:64], digestB)
	combined := sha256.Sum256(concat[:])

	return &TitanImageMetadataV2{
		Digest: combined[:],
		Major:  majorA,
	}, nil
}

// HashBundleV2FromFile parses an isolated Bundle Version 2 update bundle file path and returns its unified digest and version.
func HashBundleV2FromFile(path string) (*TitanImageMetadataV2, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("HashBundleV2FromFile failed to open file: %w", err)
	}
	defer f.Close()

	return HashBundleV2(f)
}

// alignUp rounds val up to the next multiple of align.
func alignUp(val uint32, align uint32) uint32 {
	return (val + align - 1) & ^(align - 1)
}

// readUint32 decodes a uint32 from a slice, enforcing an exact length of 4 bytes to catch slice mutations.
func readUint32(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, fmt.Errorf("invalid slice length %d for uint32 decode", len(b))
	}
	return binary.LittleEndian.Uint32(b), nil
}
