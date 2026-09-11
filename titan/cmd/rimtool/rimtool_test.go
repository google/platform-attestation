package rimtool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/platform-attestation/titan/bundlev2"
	"github.com/google/platform-attestation/titan/descriptor"
	"github.com/google/platform-attestation/titan/titanheader"
)

// =============================================================================
// 1. Symmetrical Mock Data Builders
// =============================================================================

// createMockBundleV2 generates a valid in-memory V2 bundle stream.
func createMockBundleV2(t *testing.T, magic uint32, major uint32) []byte {
	t.Helper()

	const testAlignedImageSize uint32 = 2048
	const markerIndex = 500
	const markerA = 0xAA
	const markerB = 0xBB

	desc := titanheader.TitanRegionDescriptor{
		DescriptorMagic:    titanheader.TitanHeaderMagic,
		DescriptorVersion:  1,
		AppFirmwareAOffset: 64,
		AppFirmwareASize:   testAlignedImageSize + 2048,
		AppFirmwareBOffset: 12000,
		AppFirmwareBSize:   testAlignedImageSize + 2048,
	}

	var descBuf bytes.Buffer
	if err := binary.Write(&descBuf, binary.LittleEndian, &desc); err != nil {
		t.Fatalf("createMockBundleV2 failed: %v", err)
	}
	descBytes := descBuf.Bytes()

	// Image A
	fwA := make([]byte, testAlignedImageSize)
	binary.LittleEndian.PutUint32(fwA[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], magic)
	binary.LittleEndian.PutUint32(fwA[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], testAlignedImageSize)
	binary.LittleEndian.PutUint32(fwA[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], major)
	fwA[markerIndex] = markerA
	hashA := sha256.Sum256(fwA[titanheader.TagFieldOffset:])

	// Image B
	fwB := make([]byte, testAlignedImageSize)
	binary.LittleEndian.PutUint32(fwB[titanheader.MagicFieldOffset:titanheader.MagicFieldOffset+4], magic)
	binary.LittleEndian.PutUint32(fwB[titanheader.ImageSizeFieldOffset:titanheader.ImageSizeFieldOffset+4], testAlignedImageSize)
	binary.LittleEndian.PutUint32(fwB[titanheader.MajorFieldOffset:titanheader.MajorFieldOffset+4], major)
	fwB[markerIndex] = markerB
	hashB := sha256.Sum256(fwB[titanheader.TagFieldOffset:])

	var metadata bundlev2.UnsignedMetadata
	metadata.Tag = bundlev2.UnsignedMetadataMagic // "IMG_HASH"
	metadata.StructLength = bundlev2.UnsignedMetadataLength
	metadata.RWAHash = hashA
	metadata.RWBHash = hashB

	var metaBuf bytes.Buffer
	if err := binary.Write(&metaBuf, binary.LittleEndian, &metadata); err != nil {
		t.Fatalf("createMockBundleV2 serialize failed: %v", err)
	}
	metaBytes := metaBuf.Bytes()

	trailerPage := make([]byte, 2048)
	copy(trailerPage[0:], metaBytes)

	totalSize := 0 + int64(len(descBytes)) + int64(desc.AppFirmwareBOffset) + int64(desc.AppFirmwareBSize)
	bundle := make([]byte, totalSize)

	copy(bundle[0:], descBytes)
	copy(bundle[int64(desc.AppFirmwareAOffset):], fwA)
	copy(bundle[int64(desc.AppFirmwareAOffset)+int64(testAlignedImageSize):], trailerPage)
	copy(bundle[int64(desc.AppFirmwareBOffset):], fwB)
	copy(bundle[int64(desc.AppFirmwareBOffset)+int64(testAlignedImageSize):], trailerPage)

	return bundle
}

// createMockDescriptor generates a valid BIOS/BMC descriptor structure.
func createMockDescriptor(t *testing.T) []byte {
	t.Helper()

	const alignmentOffset = 65536

	dp := descriptor.DescriptorParts{
		Descriptor: descriptor.ImageDescriptor{
			DescriptorMagic:    descriptor.DescriptorMagicLE,
			DescriptorMajor:    1,
			DescriptorMinor:    0,
			DescriptorOffset:   alignmentOffset,
			HashType:           descriptor.HashTypeSHA2_256,
			VerificationScheme: descriptor.VerificationSchemeSHA256,
			RegionCount:        1,
		},
		Regions: []descriptor.ImageRegion{
			{
				RegionOffset: 0,
				RegionSize:   1024,
			},
		},
	}
	copy(dp.Regions[0].RegionName[:], "test_region")

	var err error
	dp.Hash, err = descriptor.NewDescriptorHash(descriptor.HashTypeSHA2_256)
	if err != nil {
		t.Fatalf("createMockDescriptor: NewDescriptorHash failed: %v", err)
	}
	dp.Signature, err = descriptor.NewSignatureDigest(descriptor.VerificationSchemeSHA256)
	if err != nil {
		t.Fatalf("createMockDescriptor: NewSignatureDigest failed: %v", err)
	}

	size, err := dp.Descriptor.CalculateSize()
	if err != nil {
		t.Fatalf("createMockDescriptor: CalculateSize failed: %v", err)
	}
	dp.Descriptor.DescriptorAreaSize = uint32(size)

	var b bytes.Buffer
	b.Write(make([]byte, alignmentOffset)) // Pre-pad with 64KB of zeroes
	if _, err := dp.WriteDescriptorParts(&b); err != nil {
		t.Fatalf("Failed to build test descriptor: %v", err)
	}

	return b.Bytes()
}

// =============================================================================
// 2. Hermetic Unit Tests
// =============================================================================

// TestRunApp_TitanV2_Success checks CLI sniffing and formatting on a Titan V2 bundle.
func TestRunApp_TitanV2_Success(t *testing.T) {
	const magic = bundlev2.TitanV3Magic
	const major = 123
	bundleBytes := createMockBundleV2(t, magic, major)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "titan.bin")
	if err := os.WriteFile(path, bundleBytes, 0644); err != nil {
		t.Fatalf("Failed to write V2 mock file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"rimtool", "generate-hash", "--path=" + path}

	if err := RunApp(args, &stdout, &stderr); err != nil {
		t.Fatalf("RunApp failed unexpectedly: %v | stderr: %s", err, stderr.String())
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "Titan V2 Bundle") {
		t.Errorf("Unexpected stdout: got %q, want substring 'Titan V2 Bundle'", outStr)
	}
	if !strings.Contains(outStr, "Version: 123") {
		t.Errorf("Unexpected stdout: got %q, want substring 'Version: 123'", outStr)
	}
}

// TestRunApp_Descriptor_Success checks CLI sniffing and formatting on a BIOS/BMC descriptor.
func TestRunApp_Descriptor_Success(t *testing.T) {
	descBytes := createMockDescriptor(t)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "descriptor.bin")
	if err := os.WriteFile(path, descBytes, 0644); err != nil {
		t.Fatalf("Failed to write descriptor mock file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"rimtool", "generate-hash", "--path=" + path}

	if err := RunApp(args, &stdout, &stderr); err != nil {
		t.Fatalf("RunApp failed unexpectedly: %v | stderr: %s", err, stderr.String())
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "Image Descriptor") {
		t.Errorf("Unexpected stdout: got %q, want substring 'Image Descriptor'", outStr)
	}
	if !strings.Contains(outStr, "Hash:    SHA2_256") {
		t.Errorf("Unexpected stdout: got %q, want substring 'Hash:    SHA2_256'", outStr)
	}
}

// TestRunApp_MissingPath checks error status when path is omitted.
func TestRunApp_MissingPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"rimtool", "generate-hash"}

	err := RunApp(args, &stdout, &stderr)
	if err == nil {
		t.Fatal("RunApp succeeded, want error for missing --path flag")
	}
	if !strings.Contains(stderr.String(), "Path to the target firmware binary") {
		t.Errorf("RunApp() stderr = %q, want flag usage instructions", stderr.String())
	}
}

// TestRunApp_InvalidFile checks file load failure outcomes.
func TestRunApp_InvalidFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"rimtool", "generate-hash", "--path=non_existent.bin"}

	err := RunApp(args, &stdout, &stderr)
	if err == nil {
		t.Fatal("RunApp succeeded, want error for invalid path")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "no such file or directory") {
		t.Errorf("Unexpected error logs: got %q, want substring 'no such file or directory'", errStr)
	}
}

// TestRunApp_UnknownCommand checks CLI routing rejection.
func TestRunApp_UnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"rimtool", "invalid-subcommand"}

	err := RunApp(args, &stdout, &stderr)
	if err == nil {
		t.Fatal("RunApp succeeded, want error for invalid subcommand")
	}
	if !strings.Contains(stderr.String(), "Usage: rimtool <command>") {
		t.Errorf("RunApp() stderr = %q, want subcommand help instructions", stderr.String())
	}
}
