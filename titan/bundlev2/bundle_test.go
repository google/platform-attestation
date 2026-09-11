package bundlev2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/platform-attestation/titan/titanheader"
)

// =============================================================================
// 1. Mock Bundle & Image Helpers
// =============================================================================

// createMockBundleV2 creates a mock Bundle Version 2 update bundle. The RW image slots contain
// valid SignedHeader components, program body bytes, and the trailing UnsignedMetadata struct page.
func createMockBundleV2(t *testing.T, descriptorOffset int64, magic uint32, majorA, majorB uint32, corruptMetadata bool) []byte {
	t.Helper()

	const testAlignedImageSize uint32 = 2048 // 2KB page aligned
	const appAOffset = 64
	const appBOffset = 12000
	const markerA = 0xAA
	const markerB = 0xBB
	const markerIndex = 500

	desc := titanheader.TitanRegionDescriptor{
		DescriptorMagic:    titanheader.TitanHeaderMagic,
		DescriptorVersion:  1,
		AppFirmwareAOffset: appAOffset,
		AppFirmwareASize:   testAlignedImageSize + 2048, // program page + trailer page
		AppFirmwareBOffset: appBOffset,
		AppFirmwareBSize:   testAlignedImageSize + 2048,
	}

	var descBuf bytes.Buffer
	if err := binary.Write(&descBuf, binary.LittleEndian, &desc); err != nil {
		t.Fatalf("createMockBundleV2: failed to serialize descriptor: %v", err)
	}
	descBytes := descBuf.Bytes()

	// --- 1. Assemble image A payload ---
	fwA := make([]byte, testAlignedImageSize)
	binary.LittleEndian.PutUint32(fwA[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], magic)
	binary.LittleEndian.PutUint32(fwA[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], testAlignedImageSize)
	binary.LittleEndian.PutUint32(fwA[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], majorA)
	fwA[markerIndex] = markerA
	hashA := sha256.Sum256(fwA[titanheader.TagFieldOffset:])

	// --- 2. Assemble image B payload ---
	fwB := make([]byte, testAlignedImageSize)
	binary.LittleEndian.PutUint32(fwB[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], magic)
	binary.LittleEndian.PutUint32(fwB[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], testAlignedImageSize)
	binary.LittleEndian.PutUint32(fwB[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], majorB)
	fwB[markerIndex] = markerB
	hashB := sha256.Sum256(fwB[titanheader.TagFieldOffset:])

	// --- 3. Assemble trailing metadata struct ---
	var metadata UnsignedMetadata
	metadata.Tag = UnsignedMetadataMagic // "IMG_HASH"
	metadata.StructLength = UnsignedMetadataLength
	if corruptMetadata {
		metadata.RWAHash = [32]byte{0x11, 0x22}
		metadata.RWBHash = [32]byte{0x33, 0x44}
	} else {
		metadata.RWAHash = hashA
		metadata.RWBHash = hashB
	}

	var metaBuf bytes.Buffer
	if err := binary.Write(&metaBuf, binary.LittleEndian, &metadata); err != nil {
		t.Fatalf("createMockBundleV2: failed to serialize metadata: %v", err)
	}
	metaBytes := metaBuf.Bytes()

	// Build 2KB trailer page
	trailerPage := make([]byte, 2048)
	copy(trailerPage[0:], metaBytes)

	totalSize := descriptorOffset + int64(len(descBytes)) + int64(desc.AppFirmwareBOffset) + int64(desc.AppFirmwareBSize)
	bundle := make([]byte, totalSize)

	copy(bundle[descriptorOffset:], descBytes)

	// Slot A positioning
	slotAOffset := descriptorOffset + int64(desc.AppFirmwareAOffset)
	copy(bundle[slotAOffset:], fwA)
	copy(bundle[slotAOffset+int64(testAlignedImageSize):], trailerPage)

	// Slot B positioning
	slotBOffset := descriptorOffset + int64(desc.AppFirmwareBOffset)
	copy(bundle[slotBOffset:], fwB)
	copy(bundle[slotBOffset+int64(testAlignedImageSize):], trailerPage)

	return bundle
}

// =============================================================================
// 2. Bundle Version 2 Attestation Tests
// =============================================================================

// TestHashBundleV2_Success verifies that HashBundleV2 successfully hashes a valid Bundle Version 2 update bundle with either Titan V1 or Titan V3 magic.
func TestHashBundleV2_Success(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic uint32
	}{
		{"TitanV1", TitanV1Magic},
		{"TitanV3", TitanV3Magic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const major = 123
			const testAlignedImageSize = 2048
			const markerIndex = 500
			const markerA = 0xAA
			const markerB = 0xBB

			bundleBytes := createMockBundleV2(t, 0, tc.magic, major, major, false)
			reader := bytes.NewReader(bundleBytes)

			res, err := HashBundleV2(reader)
			if err != nil {
				t.Fatalf("HashBundleV2 failed unexpectedly: %v", err)
			}

			if res.Major != major {
				t.Errorf("HashBundleV2 returned wrong major version: got %d, want %d", res.Major, major)
			}

			// Re-generate expected firmware image a digest
			fwA := make([]byte, testAlignedImageSize)
			binary.LittleEndian.PutUint32(fwA[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], tc.magic)
			binary.LittleEndian.PutUint32(fwA[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], testAlignedImageSize)
			binary.LittleEndian.PutUint32(fwA[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], major)
			fwA[markerIndex] = markerA
			hashA := sha256.Sum256(fwA[titanheader.TagFieldOffset:])

			// Re-generate expected firmware image b digest
			fwB := make([]byte, testAlignedImageSize)
			binary.LittleEndian.PutUint32(fwB[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], tc.magic)
			binary.LittleEndian.PutUint32(fwB[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], testAlignedImageSize)
			binary.LittleEndian.PutUint32(fwB[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], major)
			fwB[markerIndex] = markerB
			hashB := sha256.Sum256(fwB[titanheader.TagFieldOffset:])

			// Concatenate and verify the joint SHA-256 digest
			var concat [64]byte
			copy(concat[0:32], hashA[:])
			copy(concat[32:64], hashB[:])
			expectedCombined := sha256.Sum256(concat[:])

			if !bytes.Equal(res.Digest, expectedCombined[:]) {
				t.Errorf("HashBundleV2 returned wrong digest:\ngot:  %x\nwant: %x", res.Digest, expectedCombined)
			}
		})
	}
}

// TestHashBundleV2_GranitePrefix verifies scanning logic finds the bundle offset at 12 under both Titan V1 and Titan V3.
func TestHashBundleV2_GranitePrefix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic uint32
	}{
		{"TitanV1", TitanV1Magic},
		{"TitanV3", TitanV3Magic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const major = 555
			const targetOffset = 12
			bundleBytes := createMockBundleV2(t, targetOffset, tc.magic, major, major, false)
			reader := bytes.NewReader(bundleBytes)

			res, err := HashBundleV2(reader)
			if err != nil {
				t.Fatalf("HashBundleV2 failed to scan when prefixed at 12: %v", err)
			}

			if res.Major != major {
				t.Errorf("HashBundleV2: wrong major loaded from offset 12 candidate: got %d, want %d", res.Major, major)
			}
		})
	}
}

// TestHashSingleFirmwareV2_Success parses a standalone Titan V1 or Titan V3 firmware image directly, verifying its UnsignedMetadata.
// We purposely use an unaligned imageSize (2050) to verify alignUp rounds up correctly.
func TestHashSingleFirmwareV2_Success(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic uint32
	}{
		{"TitanV1", TitanV1Magic},
		{"TitanV3", TitanV3Magic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const major = 777
			const imageSize uint32 = 2049
			const markerIndex = 500
			const markerCC = 0xCC

			fw := make([]byte, imageSize)
			binary.LittleEndian.PutUint32(fw[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], tc.magic)
			binary.LittleEndian.PutUint32(fw[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], imageSize)
			binary.LittleEndian.PutUint32(fw[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], major)
			fw[markerIndex] = markerCC
			hashVal := sha256.Sum256(fw[titanheader.TagFieldOffset:])

			var metadata UnsignedMetadata
			metadata.Tag = UnsignedMetadataMagic // "IMG_HASH"
			metadata.StructLength = UnsignedMetadataLength
			metadata.RWAHash = hashVal
			metadata.RWBHash = [32]byte{0xAA}

			var metaBuf bytes.Buffer
			if err := binary.Write(&metaBuf, binary.LittleEndian, &metadata); err != nil {
				t.Fatalf("Failed to serialize metadata: %v", err)
			}
			metaBytes := metaBuf.Bytes()

			alignedStart := alignUp(imageSize, AlignmentSize)
			totalSize := alignedStart + 2048
			data := make([]byte, totalSize)
			copy(data[0:], fw)
			copy(data[alignedStart:], metaBytes)

			reader := bytes.NewReader(data)
			digest, majorVer, err := HashSingleFirmwareV2(reader, 0)
			if err != nil {
				t.Fatalf("HashSingleFirmwareV2 failed: %v", err)
			}

			if majorVer != major {
				t.Errorf("HashSingleFirmwareV2: wrong major: got %d, want %d", majorVer, major)
			}
			if !bytes.Equal(digest, hashVal[:]) {
				t.Errorf("HashSingleFirmwareV2: wrong digest:\ngot:  %x\nwant: %x", digest, hashVal)
			}
		})
	}
}

// TestHashBundleV2FromFile_Success verifies the file path convenience wrapper works under both Titan V1 and Titan V3.
func TestHashBundleV2FromFile_Success(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic uint32
	}{
		{"TitanV1", TitanV1Magic},
		{"TitanV3", TitanV3Magic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const major = 123
			bundleBytes := createMockBundleV2(t, 0, tc.magic, major, major, false)
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "bundleV2.bin")
			if err := os.WriteFile(path, bundleBytes, 0644); err != nil {
				t.Fatalf("Failed to write mock bundleV2 file: %v", err)
			}

			res, err := HashBundleV2FromFile(path)
			if err != nil {
				t.Fatalf("HashBundleV2FromFile failed: %v", err)
			}

			if res.Major != 123 {
				t.Errorf("HashBundleV2FromFile returned wrong major: got %d, want %d", res.Major, 123)
			}
		})
	}
}

// TestHashBundleV2_VersionMismatch verifies that HashBundleV2 errs on drifted image versions.
func TestHashBundleV2_VersionMismatch(t *testing.T) {
	const magic = TitanV3Magic
	const majorA = 123
	const majorB = 999
	bundleBytes := createMockBundleV2(t, 0, magic, majorA, majorB, false)
	reader := bytes.NewReader(bundleBytes)

	_, err := HashBundleV2(reader)
	if err == nil {
		t.Fatal("HashBundleV2 succeeded, want error for version mismatch")
	}

	expectedErr := "firmware image A major version (123) does not match image B major version (999)"
	if !bytes.Contains([]byte(err.Error()), []byte(expectedErr)) {
		t.Errorf("HashBundleV2() error = %q, want substring %q", err.Error(), expectedErr)
	}
}

// TestHashBundleV2_MetadataMismatch verifies that a Bundle Version 2 update bundle with corrupted or mismatched
// UnsignedMetadata hashes fails cryptographic verification.
func TestHashBundleV2_MetadataMismatch(t *testing.T) {
	const magic = TitanV3Magic
	const major = 123
	bundleBytes := createMockBundleV2(t, 0, magic, major, major, true)
	reader := bytes.NewReader(bundleBytes)

	_, err := HashBundleV2(reader)
	if err == nil {
		t.Fatal("HashBundleV2 succeeded, want error for metadata mismatch")
	}

	expectedErr := "cryptographic verification failed"
	if !bytes.Contains([]byte(err.Error()), []byte(expectedErr)) {
		t.Errorf("HashBundleV2() error = %q, want substring %q", err.Error(), expectedErr)
	}
}

// TestHashSingleFirmwareV2_InvalidMagic verifies bad Titan header magic error returns.
func TestHashSingleFirmwareV2_InvalidMagic(t *testing.T) {
	const badMagic = 0x12345678
	hdr := make([]byte, titanheader.SignedHeaderSize)
	binary.LittleEndian.PutUint32(hdr[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], badMagic)

	reader := bytes.NewReader(hdr)
	_, _, err := HashSingleFirmwareV2(reader, 0)
	if err == nil {
		t.Fatal("HashSingleFirmwareV2 succeeded, want error for corrupt magic")
	}
}

// TestHashBundleV2_InvalidDescriptorMagic verifies descriptor magic mismatch errors.
func TestHashBundleV2_InvalidDescriptorMagic(t *testing.T) {
	const magic = TitanV3Magic
	const major = 123
	bundleBytes := createMockBundleV2(t, 0, magic, major, major, false)

	// Damage the descriptor magic number at the very beginning (bytes 0-8)
	binary.LittleEndian.PutUint64(bundleBytes[0:8], 0xBAAAAAAAAAD)

	reader := bytes.NewReader(bundleBytes)
	_, err := HashBundleV2(reader)
	if err == nil {
		t.Fatal("HashBundleV2 succeeded, want error for corrupt descriptor magic")
	}
	if !strings.Contains(err.Error(), "no valid TitanRegionDescriptor found") {
		t.Errorf("HashBundleV2() error = %q, want substring %q", err.Error(), "no valid TitanRegionDescriptor found")
	}
}

// TestHashSingleFirmwareV2_InvalidMetadataTag verifies metadata header tag mismatch errors.
func TestHashSingleFirmwareV2_InvalidMetadataTag(t *testing.T) {
	const magic = TitanV3Magic
	const major = 777
	const imageSize uint32 = 2049
	const markerIndex = 500
	const markerCC = 0xCC

	fw := make([]byte, imageSize)
	binary.LittleEndian.PutUint32(fw[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], magic)
	binary.LittleEndian.PutUint32(fw[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], imageSize)
	binary.LittleEndian.PutUint32(fw[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], major)
	fw[markerIndex] = markerCC
	hashVal := sha256.Sum256(fw[titanheader.TagFieldOffset:])

	var metadata UnsignedMetadata
	metadata.Tag = 0xBAAAAAAAD // bad tag magic!
	metadata.StructLength = UnsignedMetadataLength
	metadata.RWAHash = hashVal
	metadata.RWBHash = [32]byte{0xAA}

	var metaBuf bytes.Buffer
	if err := binary.Write(&metaBuf, binary.LittleEndian, &metadata); err != nil {
		t.Fatalf("Failed to serialize metadata: %v", err)
	}
	metaBytes := metaBuf.Bytes()

	alignedStart := alignUp(imageSize, AlignmentSize)
	totalSize := alignedStart + 2048
	data := make([]byte, totalSize)
	copy(data[0:], fw)
	copy(data[alignedStart:], metaBytes)

	reader := bytes.NewReader(data)
	_, _, err := HashSingleFirmwareV2(reader, 0)
	if err == nil {
		t.Fatal("HashSingleFirmwareV2 succeeded, want error for bad metadata tag")
	}
	if !strings.Contains(err.Error(), "unexpected metadata magic") {
		t.Errorf("HashSingleFirmwareV2() error = %q, want substring %q", err.Error(), "unexpected metadata magic")
	}
}

// TestHashSingleFirmwareV2_InvalidMetadataLength verifies metadata byte length mismatch errors.
func TestHashSingleFirmwareV2_InvalidMetadataLength(t *testing.T) {
	const magic = TitanV3Magic
	const major = 777
	const imageSize uint32 = 2049
	const markerIndex = 500
	const markerCC = 0xCC

	fw := make([]byte, imageSize)
	binary.LittleEndian.PutUint32(fw[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], magic)
	binary.LittleEndian.PutUint32(fw[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], imageSize)
	binary.LittleEndian.PutUint32(fw[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], major)
	fw[markerIndex] = markerCC
	hashVal := sha256.Sum256(fw[titanheader.TagFieldOffset:])

	var metadata UnsignedMetadata
	metadata.Tag = UnsignedMetadataMagic
	metadata.StructLength = 99 // bad length!
	metadata.RWAHash = hashVal
	metadata.RWBHash = [32]byte{0xAA}

	var metaBuf bytes.Buffer
	if err := binary.Write(&metaBuf, binary.LittleEndian, &metadata); err != nil {
		t.Fatalf("Failed to serialize metadata: %v", err)
	}
	metaBytes := metaBuf.Bytes()

	alignedStart := alignUp(imageSize, AlignmentSize)
	totalSize := alignedStart + 2048
	data := make([]byte, totalSize)
	copy(data[0:], fw)
	copy(data[alignedStart:], metaBytes)

	reader := bytes.NewReader(data)
	_, _, err := HashSingleFirmwareV2(reader, 0)
	if err == nil {
		t.Fatal("HashSingleFirmwareV2 succeeded, want error for bad metadata length")
	}
	if !strings.Contains(err.Error(), "unexpected metadata structural length") {
		t.Errorf("HashSingleFirmwareV2() error = %q, want substring %q", err.Error(), "unexpected metadata structural length")
	}
}
