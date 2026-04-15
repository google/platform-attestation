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
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"unsafe"
)

// ImageRegionNameNbytes is the size of name used including a '\0' terminator.
const ImageRegionNameNbytes = 32

// ImageRegionNameDescriptor is the magic name that identifies the image descriptor region.
const ImageRegionNameDescriptor = "image_descriptor"

// ImageRegion describes a part of the firmware image.
// There are no padding bytes, i.e. size must equal the sum of the size of the fields.
type ImageRegion struct {
	RegionName   [ImageRegionNameNbytes]uint8 // null-terminated ASCII string
	RegionOffset uint32
	RegionSize   uint32
	/* Regions will not be persisted across different versions.
	* This field is intended to flag potential incompatibilities in the
	* context of data migration (e.g. the ELOG format changed between
	* two BIOS releases).
	 */
	RegionVersion uint16
	/* See IMAGE_REGION_* defines above. */
	RegionAttributes RegionAttribute
}

// String representation of an ImageRegion.
func (ir ImageRegion) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "{\n")
	fmt.Fprintf(&b, "  RegionName: %s\n", string(bytes.Trim(ir.RegionName[:], "\x00")))
	fmt.Fprintf(&b, "  RegionOffset: 0x%08x\n", ir.RegionOffset)
	fmt.Fprintf(&b, "  RegionSize: 0x%08x\n", ir.RegionSize)
	fmt.Fprintf(&b, "  RegionVersion: 0x%04x\n", ir.RegionVersion)
	fmt.Fprintf(&b, "  RegionAttributes: 0x%04x\n", ir.RegionAttributes)
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// Align returns an ImageDescriptorAlignment aligned address at or below the given address.
func Align(addr uint32) uint32 {
	return addr &^ (Alignment - 1)
}

// ImageDescriptor main structure (major=1, minor=0). Verification process:
// - Hash(image_descriptor + region_count * struct image_region +
//
//	struct hash_* + struct blob + uint8_t blob[blob_size])
//
// - Verify the signature_* over the hash computed in the previous step
// - Compute the rolling hash of the regions marked IMAGE_REGION_STATIC
// - The image descriptor is excluded from the hash (descriptor_size bytes)
// - Compare the computed hash to the struct hash_*.hash
// N.B. all fields are exported so that binary encode catches padding, etc.
type ImageDescriptor struct {

	// DescriptorMagic must be 0x5f435344474d495f (LE) = "_IMGDSC_"
	DescriptorMagic uint64
	// DescriptorMajor structure version; no backward compatibility.
	DescriptorMajor uint8
	// DescriptorMinor revisions are backwards compatible.
	DescriptorMinor uint8
	// Reserved0 is padding
	Reserved0 uint16 // set to zeros

	// DescriptorOffset allows us to mitigate a DOS vector if we end up
	// scanning the image to discover the image descriptor. The offset
	// and size are hashed with the rest of the descriptor to prevent
	// an attacker from copying a valid descriptor to a different
	// location.
	//
	// The offset is relative to the start of the image data.
	DescriptorOffset uint32
	// DescriptorAreaSize includes this struct as well as the auxiliary
	// structs (hash_*, signature_*, and blob). This many bytes will
	// be skipped when computing the hash of the region this struct resides
	// in. Tail padding is allowed but must be all 0xff's.
	DescriptorAreaSize uint32

	// Image information.

	// ImageName is a null-terminated ASCII string.
	// For BIOS this would be the platform
	ImageName [ImageNameNbytes]uint8
	// ImageFamily is used to enforce like to like image updates.
	// 0 is treated as a wildcard (can upgrade to/from any image family).
	// See ImageFamily "enum" above.
	ImageFamily ImageFamily
	// ImageMajor is a Kibbles-style major version number.
	ImageMajor uint32
	// ImageMinor is a Kibbles-style minor version number.
	ImageMinor uint32
	// ImagePoint is a Kibbles-style point version number.
	ImagePoint uint32
	// ImageSubpoint is a Kibbles-style subpoint version number.
	ImageSubpoint uint32
	// BuildTimestamp is the number of seconds since epoch.
	BuildTimestamp uint64

	// ImageType is selected from ImageType "enum" { DEV, PROD, BREAKOUT, UNSIGNED_INTEGRITY }
	ImageType ImageType
	// DenylistSize is the number of Denylist entries that follow.
	// 0: no denylist struct, 1: watermark only, >1: watermark + denylist
	DenylistSize uint8
	// HashType is from the HashType "enum" and is
	// one of { NONE, SHA2_224, SHA2_256, ...}
	HashType HashType
	// VerificationScheme is from the VerificationScheme "enum".
	// If set HashType must be set as well (cannot be NONE).
	VerificationScheme VerificationScheme

	// RegionCount is the number of Region structs to follow this struct
	RegionCount uint8
	// Reserved1 is padding. (exported for the sake of binary encode/decode)
	Reserved1 uint8
	// Reserved2 is padding. (exported for the sake of binary encode/decode)
	Reserved2 uint16
	// ImageSize is the sum of the ImageRegion.RegionSize fields
	ImageSize uint32
	// BlobSize is authenticated opaque data exposed to system software
	// (e.g. ProdID tokens). Must be a multiple of 4 to maintain alignment.
	BlobSize uint32
	// The list is strictly ordered by region_offset.
	// Must exhaustively describe the image.
	// ImageRegions []ImageRegion are not included as a variable length
	// array in order to avoid structure size/alignment issues for
	// encoding and decoding.
}

// CalculateSize calculates the size of the image descriptor area.
func (id ImageDescriptor) CalculateSize() (int, error) {
	total := 0
	total += int(unsafe.Sizeof(ImageDescriptor{}))
	total += int(id.RegionCount) * int(unsafe.Sizeof(ImageRegion{}))
	switch id.VerificationScheme {
	case VerificationSchemeRSA2048PKCS15SHA256:
		total += int(unsafe.Sizeof(SignatureRSA2048PKCS1_5{}))
	case VerificationSchemeRSA3072PKCS15SHA256:
		total += int(unsafe.Sizeof(SignatureRSA3072PKCS1_5{}))
	case VerificationSchemeRSA4096PKCS15SHA256:
		total += int(unsafe.Sizeof(SignatureRSA4096PKCS1_5{}))
	case VerificationSchemeRSA4096PKCS15SHA512:
		total += int(unsafe.Sizeof(SignatureRSA4096PKCS15SHA512{}))
	case VerificationSchemeSHA256:
		total += int(unsafe.Sizeof(SHA256{}))
	case VerificationSchemeNone:
	default:
		return 0, fmt.Errorf("unknown signature scheme: %v", id.VerificationScheme)
	}
	switch id.HashType {
	case HashTypeSHA2_256:
		total += int(unsafe.Sizeof(HashSHA256{}))
	case HashTypeNone:
	case HashTypeSHA2_224:
		total += 4 + 224/8
	case HashTypeSHA2_384:
		total += 4 + 384/8
	case HashTypeSHA2_512:
		total += 4 + 512/8
	case HashTypeSHA3_224:
		total += 4 + 224/8
	case HashTypeSHA3_256:
		total += 4 + 256/8
	case HashTypeSHA3_384:
		total += 4 + 384/8
	case HashTypeSHA3_512:
		total += 4 + 512/8
	default:
		return 0, fmt.Errorf("unknown hash type: %v", id.HashType)
	}
	if id.BlobSize > 0 {
		total += int(unsafe.Sizeof(Blob{})) + int(id.BlobSize)
	}
	return total, nil
}

// String representation of an ImageDescriptor.
func (id ImageDescriptor) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "{\n")
	fmt.Fprintf(&b, "  DescriptorMagic: 0x%08x\n", id.DescriptorMagic)
	fmt.Fprintf(&b, "  DescriptorMajor: 0x%02x\n", id.DescriptorMajor)
	fmt.Fprintf(&b, "  DescriptorMinor: 0x%02x\n", id.DescriptorMinor)
	fmt.Fprintf(&b, "  Reserved0: 0x%04x\n", id.Reserved0)
	fmt.Fprintf(&b, "  DescriptorOffset: 0x%08x\n", id.DescriptorOffset)
	fmt.Fprintf(&b, "  DescriptorAreaSize: 0x%08x\n", id.DescriptorAreaSize)
	fmt.Fprintf(&b, "  ImageName: \"%s\"\n", string(id.ImageName[:]))
	fmt.Fprintf(&b, "  ImageFamily: %d\n", id.ImageFamily)
	fmt.Fprintf(&b, "  ImageMajor: 0x%08x\n", id.ImageMajor)
	fmt.Fprintf(&b, "  ImageMinor: 0x%08x\n", id.ImageMinor)
	fmt.Fprintf(&b, "  ImagePoint: 0x%08x\n", id.ImagePoint)
	fmt.Fprintf(&b, "  ImageSubpoint: 0x%08x\n", id.ImageSubpoint)
	fmt.Fprintf(&b, "  BuildTimestamp: 0x%016x\n", id.BuildTimestamp)
	fmt.Fprintf(&b, "  ImageType: %s(%d)\n", ImageTypeName[id.ImageType], id.ImageType)
	fmt.Fprintf(&b, "  DenyListSize: 0x%02x\n", id.DenylistSize)
	fmt.Fprintf(&b, "  HashType: %s(%d)\n", HashTypeName[id.HashType], id.HashType)
	fmt.Fprintf(&b, "  VerificationScheme: %s(%d)\n", VerificationSchemeName[id.VerificationScheme], id.VerificationScheme)
	fmt.Fprintf(&b, "  RegionCount: 0x%02x\n", id.RegionCount)
	fmt.Fprintf(&b, "  Reserved1: 0x%02x\n", id.Reserved1)
	fmt.Fprintf(&b, "  Reserved2: 0x%04x\n", id.Reserved2)
	fmt.Fprintf(&b, "  ImageSize: 0x%08x\n", id.ImageSize)
	fmt.Fprintf(&b, "  BlobSize: 0x%08x\n", id.BlobSize)

	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// ReadImageDescriptor reads the base structure from an image descriptor.
func ReadImageDescriptor(r io.Reader) (*ImageDescriptor, error) {
	var desc ImageDescriptor

	err := binary.Read(r, binary.LittleEndian, &desc)
	if err != nil {
		return nil, err
	}
	if desc.DescriptorMagic != DescriptorMagicLE {
		return nil, fmt.Errorf("invalid descriptor magic(0x%16x)", desc.DescriptorMagic)
	}
	if ImageTypeName[desc.ImageType] == "" {
		return nil, fmt.Errorf("invalid image_type %d", desc.ImageType)
	}
	if HashTypeName[desc.HashType] == "" {
		return nil, fmt.Errorf("invalid hash_type %d", desc.HashType)
	}
	if VerificationSchemeName[desc.VerificationScheme] == "" {
		return nil, fmt.Errorf("invalid signature_scheme %d", desc.VerificationScheme)
	}

	return &desc, nil
}

// ReadImageDescriptorRegions reads in the variable part of the image_descriptor.
// Being fixed length, properly aligned structures, we can read them in.
// directly.
func ReadImageDescriptorRegions(r io.Reader, n int) ([]ImageRegion, error) {
	regions := make([]ImageRegion, n)
	for i := 0; i < n; i++ {
		err := binary.Read(r, binary.LittleEndian, &regions[i])
		if err != nil {
			return nil, err
		}
	}
	return regions, nil
}

// ReadHash reads the optional hash structure from an image descriptor.
func ReadHash(r io.Reader, ht HashType) (DescriptorHash, error) {
	hash, err := NewDescriptorHash(ht)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.LittleEndian, hash)
	if err != nil {
		return nil, err
	}
	if hash.Magic() != HashMagicLE {
		// optional structure is not present
		return nil, nil
	}
	return hash, nil
}

// ReadBlob reads the optional binary blob from an image descriptor.
func ReadBlob(r io.Reader, n int) (*Blob, error) {
	fixed := make([]byte, n+4)
	_, err := io.ReadFull(r, fixed)
	if err != nil {
		return nil, err
	}
	off := 0
	magic := binary.LittleEndian.Uint32(fixed[off : off+4])
	off += 4
	if magic != BlobMagicLE {
		// optional blob does not exist, an error at the caller,
		// not here.
		return nil, nil
	}
	var blob Blob
	blob.BlobMagic = magic
	blob.Blob = fixed[off:]
	return &blob, nil
}

// DescriptorParts is the collection of structures that may occur as part of the CR51 Image Descriptor.
type DescriptorParts struct {
	// Descriptor is the mandatory base structure.
	Descriptor ImageDescriptor
	// Regions holds description of the various firmware regions.
	Regions []ImageRegion
	// Hash (optional) is the firmware image hash.
	Hash DescriptorHash
	// Denylist (optional) describes firmware versions to be rejected
	Denylist *Denylist
	// Blob (optional) describes a data blob.
	Blob *Blob
	// SignatureRSA2048PKCS1_5 selects that signing algo.
	// Signature or digest over the image descriptor itself.
	Signature SignatureRSAOrDigest
}

// String representation of DescriptorParts.
func (dp DescriptorParts) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "DescriptorParts{\n")
	fmt.Fprintf(&b, "  Descriptor: %v\n", dp.Descriptor)
	fmt.Fprintf(&b, "  Regions: %v\n", dp.Regions)
	fmt.Fprintf(&b, "  Hash: %v\n", dp.Hash)
	fmt.Fprintf(&b, "  Denylist: %v\n", dp.Denylist)
	fmt.Fprintf(&b, "  Blob: %v\n", dp.Blob)
	fmt.Fprintf(&b, "  Signature: %v\n", dp.Signature)
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// ReadDescriptorParts read the entire collection of structures from a binary image descriptor.
func ReadDescriptorParts(r io.ReadSeeker) (DescriptorParts, error) {
	dp := DescriptorParts{}
	desc, err := ReadImageDescriptor(r)
	if err != nil {
		return dp, err
	}
	dp.Descriptor = *desc
	regions, err := ReadImageDescriptorRegions(r, int(dp.Descriptor.RegionCount))
	dp.Regions = regions
	if err != nil {
		return dp, err
	}

	// Parse optional hash structure
	savedOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return dp, err
	}
	hash, err := ReadHash(r, dp.Descriptor.HashType)
	if err != nil {
		return dp, err
	}
	if hash == nil {
		_, err = r.Seek(savedOffset, io.SeekStart)
		if err != nil {
			return dp, err
		}
	}
	dp.Hash = hash

	// Parse optional blob
	if dp.Descriptor.BlobSize > 0 {
		var blob *Blob
		blob, err = ReadBlob(r, int(dp.Descriptor.BlobSize))
		if err != nil {
			return dp, err
		}
		if blob == nil {
			err = fmt.Errorf("blob size specified as %d but blob is not present", dp.Descriptor.BlobSize)
			return dp, err
		}
		dp.Blob = blob
	}

	// Parse optional signature
	// Signature is not present for Signature_None, otherwise, it is required.
	var sig SignatureRSAOrDigest
	// LINT.IfChange
	if dp.Descriptor.VerificationScheme == VerificationSchemeSHA256 {
		sig, err = NewSignatureDigest(dp.Descriptor.VerificationScheme)
	} else {
		sig, err = NewSignatureRSA(dp.Descriptor.VerificationScheme, 0, 0, 0, nil)
	}
	// LINT.ThenChange(//depot/google3/platforms/security/titan/gq/keyinfo.go)
	if err != nil {
		return dp, err
	}
	dp.Signature = sig
	err = dp.Signature.Read(r)
	if err != nil {
		return dp, err
	}
	return dp, err
}

// WriteDescriptorParts writes out a Titan compatible binary structure.
// containing the image_descriptor from cr51_image_descriptor.h
// nsig is the number of trailing bytes containing the signature.
func (dp *DescriptorParts) WriteDescriptorParts(w io.Writer) (int, error) {
	nsig := 0
	err := binary.Write(w, binary.LittleEndian, dp.Descriptor)
	if err != nil {
		return 0, err
	}
	if dp.Descriptor.RegionCount == 0 || dp.Regions == nil {
		return 0, fmt.Errorf("zero regions to write or nil regions: %d, %v", dp.Descriptor.RegionCount, dp.Regions)
	}
	for i := 0; i < int(dp.Descriptor.RegionCount); i++ {
		err = binary.Write(w, binary.LittleEndian, dp.Regions[i])
		if err != nil {
			return 0, err
		}
	}
	err = binary.Write(w, binary.LittleEndian, dp.Hash)
	if err != nil {
		return 0, err
	}
	if dp.Descriptor.BlobSize > 0 {
		if dp.Blob == nil {
			return 0, fmt.Errorf("blob_size=%d, dp.Blob == nil", dp.Descriptor.BlobSize)
		}
		fixed := make([]byte, 4)
		binary.LittleEndian.PutUint32(fixed[:], BlobMagicLE)
		var n int
		n, err = w.Write(fixed[:])
		if err != nil {
			return 0, err
		}
		if n != 4 {
			return 0, fmt.Errorf("incorrect write size %d for BlobMagic", n)
		}
		if len((dp.Blob.Blob)[:]) != int(dp.Descriptor.BlobSize) {
			return 0, fmt.Errorf("len(dp.Blob.Blob)=%d != dp.Descriptor.BlobSize(%d)", len((dp.Blob.Blob)[:]), dp.Descriptor.BlobSize)
		}
		n, err = w.Write((dp.Blob.Blob)[:])
		if err != nil {
			return 0, err
		}
		if n != len((dp.Blob.Blob)[:]) {
			return 0, fmt.Errorf("incorrect write size %d for Blob data(%d)", n, len((dp.Blob.Blob)[:]))
		}
	}
	if dp.Signature == nil {
		return 0, fmt.Errorf("missing %v", dp.Descriptor.VerificationScheme)
	}
	err = binary.Write(w, binary.LittleEndian, dp.Signature)
	if err != nil {
		return 0, fmt.Errorf("cannot write signature: %v", err)
	}
	nsig = len(dp.Signature.SignatureValue())
	return nsig, nil
}

// ImageDescriptorHash struct holds the CR51 image descriptor hash and its hash type.
type ImageDescriptorHash struct {
	digest   []byte
	hashType HashType
}

// Digest returns the CR51 image descriptor hash digest.
func (descHash ImageDescriptorHash) Digest() []byte {
	return descHash.digest
}

// ReadImageDescriptor reads the image descriptor file and translates the bytes into the
// imagedescriptor.DescriptorParts struct.
func ReadImageDescriptorFile(ctx context.Context, path string) (*DescriptorParts, error) {
	descriptor, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error %v: failed to read image descriptor file from %v", err, path)
	}
	buf := bytes.NewReader(descriptor)
	parts, err := ReadDescriptorParts(buf)
	if err != nil {
		return nil, fmt.Errorf("error %v: failed to deserialize image descriptor parts", err)
	}
	return &parts, nil
}

// getBlobHash returns the hash of the blob with the appropriate hash type.
func getBlobHash(hashType HashType, blob []byte) ([]byte, error) {
	var hash hash.Hash
	switch hashType {
	case HashTypeSHA2_256:
		hash = crypto.SHA256.New()
	case HashTypeSHA2_512:
		hash = crypto.SHA512.New()
	default:
		return nil, fmt.Errorf("error: hash type %v not supported in ProdID Metadata", hashType)
	}

	hash.Write(blob)
	return hash.Sum(nil), nil
}

// SerializeImageDescriptor serializes the image descriptor and returns the
// resulting bytes and number of those that are trailing signature bytes.
func SerializeImageDescriptor(idesc *DescriptorParts) ([]byte, int, error) {
	// Serialize the Image descriptor to find its size
	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	nsig, err := idesc.WriteDescriptorParts(w)
	if err != nil {
		return nil, 0, err
	}
	w.Flush()
	return b.Bytes(), nsig, err
}

// GetImageDescriptorHash computes the hash of the image descriptor without the signature.
// The signature is not included because the hash value should match what the Titan
// firmware will measure.
func GetImageDescriptorHash(parts *DescriptorParts) (*ImageDescriptorHash, error) {
	var err error
	var idblob []byte
	var nsig int
	var hash []byte

	if idblob, nsig, err = SerializeImageDescriptor(parts); err != nil {
		return nil, fmt.Errorf("error %v: failed to serialize image descriptor", err)
	}
	if len(idblob) < nsig {
		return nil, fmt.Errorf("the descriptor's length is smaller than the signature's length: "+
			"blob_len=%d sig_len=%d blob=%v", len(idblob), nsig, idblob)
	}
	// Return the serialized image descriptor without the signature portion
	if hash, err = getBlobHash(parts.Hash.Type(), idblob[0:len(idblob)-nsig]); err != nil {
		return nil, fmt.Errorf("error %v: failed to get blob hash", err)
	}
	return &ImageDescriptorHash{hash, parts.Hash.Type()}, nil
}
