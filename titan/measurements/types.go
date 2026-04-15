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
	"encoding/binary"
)

// RegionAttribute is a bitmask of region properties.
type RegionAttribute uint16

// Image region attributes.
const (
	// ImageregionStatic region is hashed and signed.
	ImageRegionStatic RegionAttribute = (1 << 0)
	// ImageregionCompressed UEFI compatibility.
	ImageRegionCompressed = (1 << 1)
	// ImageRegionWriteProtected Titan will quash writes
	ImageRegionWriteProtected = 0x1
	// ImageRegionReadProtected Titan will quash reads
	ImageRegionReadProtected = 0x2
	// ImageRegionPersistent feature under development for A/B updates
	ImageRegionPersistent = (1 << 4)
	// ImageRegionPersistent feature under development for A/B updates
	ImageRegionPersistentRelocatable = (1 << 5)
	// ImageRegionPersistentRelocatable feature under development for A/B updates
	ImageRegionPersistentExpandable = (1 << 6)
	// Allows overwrite of region previously marked as persistent
	ImageRegionOverride = (1 << 7)
	// Replace region by new image even if it is marked as persistent
	ImageRegionOverrideOnTransition = (1 << 8)
	// A region to be used for the dynamic mailbox
	ImageRegionMailbox = (1 << 9)
	// A static region with this flag doesn't need to be hashed on boot
	ImageRegionSkipBootValidation = (1 << 10)
	// An empty region that does not need to be updated on payload update
	ImageRegionEmpty = (1 << 11)
)

// MailboxMagic magic number fills a mailbox region
const MailboxMagic = "_HVNMAIL"

// LINT.IfChange
// ImageRegionProtected gives alignment and size constraints for protected pages.
const (
	ImageRegionProtectedAlignment = 4096
	ImageRegionProtectedPageSize  = 4096
	ImageRegionMailboxAlignment   = 65536
	ImageRegionCountMaximum       = 16
)

// ImageType specifies key type used to sign, prod(uction) or some other type.
type ImageType uint8

// ImageType is usually development (dev) or production (prod).
const (
	ImageTypeDev               ImageType = 0
	ImageTypeProd                        = 1
	ImageTypeBreakout                    = 2
	ImageTypeTest                        = 3
	ImageTypeUnsignedIntegrity           = 4
)

// ImageTypeName gives names to ImageType enums.
var ImageTypeName = map[ImageType]string{
	ImageTypeDev:               "dev",
	ImageTypeProd:              "prod",
	ImageTypeBreakout:          "breakout",
	ImageTypeTest:              "test",
	ImageTypeUnsignedIntegrity: "unsigned_integrity",
}

// ImageTypeID is the reverse map of ImageTypeName.
var ImageTypeID = map[string]ImageType{}

func init() {
	for k, v := range ImageTypeName {
		ImageTypeID[v] = k
	}
}

// HashType specifies the hash algorithm used in signing the image.
type HashType uint8

// Hash algorithms used for signing.
const (
	HashTypeNone     HashType = 0
	HashTypeSHA2_224          = 1
	HashTypeSHA2_256          = 2
	HashTypeSHA2_384          = 3
	HashTypeSHA2_512          = 4
	HashTypeSHA3_224          = 5
	HashTypeSHA3_256          = 6
	HashTypeSHA3_384          = 7
	HashTypeSHA3_512          = 8
)

// HashTypeName provides "enum" to string mapping.
var HashTypeName = map[HashType]string{
	HashTypeNone:     "None",
	HashTypeSHA2_224: "SHA2_224",
	HashTypeSHA2_256: "SHA2_256",
	HashTypeSHA2_384: "SHA2_384",
	HashTypeSHA2_512: "SHA2_512",
	HashTypeSHA3_224: "SHA3_224",
	HashTypeSHA3_256: "SHA3_256",
	HashTypeSHA3_384: "SHA3_384",
	HashTypeSHA3_512: "SHA3_512",
}

// ImageFamily specifies a particular board type for firmware compatibility.
// or All if used on all boards.
type ImageFamily uint32

// VerificationScheme specifies the signature algorithm used in signing the image.
type VerificationScheme uint8

// Signature algorithms supported.
const (
	VerificationSchemeNone                VerificationScheme = 0
	VerificationSchemeRSA2048PKCS15SHA256 VerificationScheme = 1
	VerificationSchemeRSA3072PKCS15SHA256 VerificationScheme = 2
	VerificationSchemeRSA4096PKCS15SHA256 VerificationScheme = 3
	VerificationSchemeRSA4096PKCS15SHA512 VerificationScheme = 4
	VerificationSchemeSHA256              VerificationScheme = 5
)

type SchemeName string

// VerificationSchemeName maps "enum" to readable string.
var VerificationSchemeName = map[VerificationScheme]SchemeName{
	VerificationSchemeNone:                "",
	VerificationSchemeRSA2048PKCS15SHA256: "rsa2048_pkcs15_sha256",
	VerificationSchemeRSA3072PKCS15SHA256: "rsa3072_pkcs15_sha256",
	VerificationSchemeRSA4096PKCS15SHA256: "rsa4096_pkcs15_sha256",
	VerificationSchemeRSA4096PKCS15SHA512: "rsa4096_pkcs15_sha512",
	VerificationSchemeSHA256:              "sha256",
}

// VerificationSchemeType is the reverse map of VerificationSchemeName.
var VerificationSchemeType = map[SchemeName]VerificationScheme{}

func init() {
	for k, v := range VerificationSchemeName {
		VerificationSchemeType[v] = k
	}
}

// DescriptorMagicLE magic number identifying an image descriptor.
var DescriptorMagicLE = binary.LittleEndian.Uint64([]byte("_IMGDSC_"))

// ImageNameNbytes is the size of name used including a '\0' terminator.
const ImageNameNbytes = 32

// DescriptorMajorDefault identifies the current implementation.
const DescriptorMajorDefault = 1

// DescriptorMinorDefault identifies the current implementation.
const DescriptorMinorDefault = 0

// Alignment ImageDescriptors must be aligned to 64kB boundaries.
const Alignment = uint32(0x10000)

// The currently supported structure format is 1.0.
// Minor number changes are backward compatible.
// Major number changes break compatibility.
const (
	CurrentDescriptorMajor = 1
	CurrentDescriptorMinor = 0
)

// DenylistMagicLE identifies a denylist.
var DenylistMagicLE = binary.LittleEndian.Uint32([]byte("BLCK"))

// DenylistRecord lists a version to be rejected during update.
type DenylistRecord struct {
	ImageMajor    uint32
	ImageMinor    uint32
	ImagePoint    uint32
	ImageSubpoint uint32
}

// Denylist collects all versions to be rejected.
type Denylist struct {
	DenylistMagic uint32
	// []DenylistRecord
	DenylistRecord *[]DenylistRecord // take care when serializing
}

// BlobMagicLE is the magic number identifying a data blob.
var BlobMagicLE = binary.LittleEndian.Uint32([]byte("BLOB"))

// Blob carries a sequence of BlobDataHeader and opaque payload data.
type Blob struct {
	BlobMagic uint32
	Blob      []byte // take care writing this out
}

// BlobData is contained in Blob, above.
type BlobData struct {
	Magic uint32
	Data  []byte
}
