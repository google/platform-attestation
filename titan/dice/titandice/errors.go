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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrMissingCertChain indicates that the certificate chain is missing.
	ErrMissingCertChain = status.Error(codes.InvalidArgument, "missing certificate chain")

	// ErrMissingAKC indicates that the AliasKeyCertificate is missing.
	ErrMissingAKC = status.Error(codes.InvalidArgument, "missing AliasKeyCertificate")

	// ErrMissingAKHC indicates that the AliasKeyHprivCertificate is missing.
	ErrMissingAKHC = status.Error(codes.InvalidArgument, "missing AliasKeyHprivCertificate")

	// ErrMissingDIDC indicates that the DeviceIdCertificate is missing.
	ErrMissingDIDC = status.Error(codes.InvalidArgument, "missing DeviceIdCertificate")

	// ErrMissingDIDSC indicates that the DeviceIdScribeCertificate is missing.
	ErrMissingDIDSC = status.Error(codes.InvalidArgument, "missing DeviceIdScribeCertificate")

	// ErrMissingEKC indicates that the EndorsementKeyCertificate is missing.
	ErrMissingEKC = status.Error(codes.InvalidArgument, "missing EndorsementKeyCertificate")

	// ErrMissingFH indicates that the FwHash is missing.
	ErrMissingFH = status.Error(codes.InvalidArgument, "missing FwHash")

	// ErrMissingHKC indicates that the TitanKeyCertificate is missing.
	ErrMissingHKC = status.Error(codes.InvalidArgument, "missing TitanKeyCertificate")

	// ErrMissingValidateOpts indicates that the ValidateScribeCertificateChainOptions is missing.
	ErrMissingValidateOpts = status.Error(codes.InvalidArgument, "missing ValidateScribeCertificateChainOptions")

	// ErrAKCSignatureVersion indicates that the AliasKeyCertificate contains an invalid SignatureVersion.
	ErrAKCSignatureVersion = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.SignatureVersion")

	// ErrAKCSignaturePurpose indicates that the AliasKeyCertificate contains an invalid SignaturePurpose.
	ErrAKCSignaturePurpose = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.SignaturePurpose")

	// ErrAKCKeyType indicates that the AliasKeyCertificate contains an invalid KeyType.
	ErrAKCKeyType = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.KeyType")

	// ErrAKCKeyOp indicates that the AliasKeyCertificate contains an invalid KeyOp.
	ErrAKCKeyOp = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.KeyOp")

	// ErrAKCKeyAlg indicates that the AliasKeyCertificate contains an invalid KeyAlg.
	ErrAKCKeyAlg = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.KeyAlg")

	// ErrAKCReserved0 indicates that the AliasKeyCertificate contains an invalid Reserved0.
	ErrAKCReserved0 = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.Reserved0")

	// ErrAKCPubKeySize indicates that the AliasKeyCertificate contains an invalid PubKeySize.
	ErrAKCPubKeySize = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.PubKeySize")

	// ErrAKCReserved1 indicates that the AliasKeyCertificate contains an invalid Reserved1.
	ErrAKCReserved1 = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.Reserved1")

	// ErrAKCExtensionHeaderType indicates that the AliasKeyCertificate contains an invalid ExtensionHeaderType.
	ErrAKCExtensionHeaderType = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.ExtensionHeaderType")

	// ErrAKCCertValidity indicates that the AliasKeyCertificate contains an invalid CertValidity.
	ErrAKCCertValidity = status.Error(codes.InvalidArgument, "bad AliasKeyCertificate.CertValidity")

	// ErrAKCHWCat indicates that the AliasKeyCertificate HwCat does not match the DeviceIdCertificate HwCat.
	ErrAKCHWCat = status.Error(codes.InvalidArgument, "AliasKeyCertificate.HwCat does not match DeviceIdCertificate")

	// ErrAKCHWID indicates that the AliasKeyCertificate HwId does not match the DeviceIdCertificate HwId.
	ErrAKCHWID = status.Error(codes.InvalidArgument, "AliasKeyCertificate.HwId does not match DeviceIdCertificate")

	// ErrAKCBootloaderTag indicates that the AliasKeyCertificate BootloaderTag does not match the DeviceIdCertificate BootloaderTag.
	ErrAKCBootloaderTag = status.Error(codes.InvalidArgument, "AliasKeyCertificate.BootloaderTag does not match DeviceIdCertificate")

	// ErrAKCKeyInfo indicates that the AliasKeyCertificate KeyInfo does not match the DeviceIdCertificate public key.
	ErrAKCKeyInfo = status.Error(codes.InvalidArgument, "AliasKeyCertificate.KeyInfo does not match DeviceIdCertificate public key")

	// ErrAKCSignature indicates that the AliasKeyCertificate Signature does not validate using the DeviceIdCertificate public key.
	ErrAKCSignature = status.Error(codes.InvalidArgument, "AliasKeyCertificate.Signature does not validate with DeviceIdCertificate public key")

	// ErrAKHCCertHash indicates that the AliasKeyHprivCertificate contains an invalid CertHash.
	ErrAKHCCertHash = status.Error(codes.InvalidArgument, "bad AliasKeyHprivCertificate.CertHash")

	// ErrAKHCHpubKey indicates that the AliasKeyHprivCertificate contains an invalid HpubKey.
	ErrAKHCHpubKey = status.Error(codes.InvalidArgument, "bad AliasKeyHprivCertificate.HpubKey")

	// ErrAKHCSignature indicates that the AliasKeyHprivCertificate Signature does not validate using the TitanKeyCertificate public key.
	ErrAKHCSignature = status.Error(codes.InvalidArgument, "AliasKeyHprivCertificate.Signature does not validate with TitanKeyCertificate public key")

	// ErrDIDCHWID0 indicates that the DeviceIdCertificate HwId is 0, indicating possible flash corruption.
	ErrDIDCHWID0 = status.Error(codes.DataLoss, "Device ID Certificate hardware ID is 0, possible flash corruption")

	// ErrDIDCSignatureVersion indicates that the DeviceIdCertificate contains an invalid SignatureVersion.
	ErrDIDCSignatureVersion = status.Error(codes.InvalidArgument, "bad DeviceIdCertificate.SignatureVersion")

	// ErrDIDCSignaturePurpose indicates that the DeviceIdCertificate contains an invalid SignaturePurpose.
	ErrDIDCSignaturePurpose = status.Error(codes.InvalidArgument, "bad DeviceIdCertificate.SignaturePurpose")

	// ErrDIDCKeyType indicates that the DeviceIdCertificate contains an invalid KeyType.
	ErrDIDCKeyType = status.Error(codes.InvalidArgument, "bad DeviceIdCertificate.KeyType")

	// ErrDIDCKeyOp indicates that the DeviceIdCertificate contains an invalid KeyOp.
	ErrDIDCKeyOp = status.Error(codes.InvalidArgument, "bad DeviceIdCertificate.KeyOp")

	// ErrDIDCKeyAlg indicates that the DeviceIdCertificate contains an invalid KeyAlg.
	ErrDIDCKeyAlg = status.Error(codes.InvalidArgument, "bad DeviceIdCertificate.KeyAlg")

	// ErrDIDCExtensionHeaderType indicates that the DeviceIdCertificate contains an invalid ExtensionHeaderType.
	ErrDIDCExtensionHeaderType = status.Error(codes.InvalidArgument, "bad DeviceIdCertificate.ExtensionHeaderType")

	// ErrDIDCSignedDataSize indicates that the DeviceIdCertificate contains an invalid SignedDataSize.
	ErrDIDCSignedDataSize = status.Error(codes.InvalidArgument, "bad DeviceIdCertificate.SignedDataSize")

	// ErrDIDCScribeKeyID indicates that the DeviceIdCertificate contains a non-trusted ScribeKeyID.
	ErrDIDCScribeKeyID = status.Error(codes.InvalidArgument, "bad DeviceIdCertificate.ScribeKeyID")

	// ErrDIDCScribeKeyInfo indicates that the DeviceIdCertificate KeyInfo does not match the ScribeCertificate public key.
	ErrDIDCScribeKeyInfo = status.Error(codes.InvalidArgument, "DeviceIdCertificate.KeyInfo does not match ScribeCertificate public key")

	// ErrDIDCScribeType indicates that the ScribeCertificate used to sign the DeviceIdCertificate is not a payload signing key.
	ErrDIDCScribeType = status.Error(codes.InvalidArgument, "bad ScribeCertificate.Magic")

	// ErrDIDCSignature indicates that the DeviceIdCertificate Signature does not validate using the ScribeCertificate public key.
	ErrDIDCSignature = status.Error(codes.InvalidArgument, "DeviceIdCertificate.Signature does not validate with ScribeCertificate public key")

	// ErrDIDSCCertHash indicates that the DeviceIdScribeCertificate contains an invalid CertHash.
	ErrDIDSCCertHash = status.Error(codes.InvalidArgument, "bad DeviceIdScribeCertificate.CertHash")

	// ErrDIDSCScribeKey indicates that the DeviceIdScribeCertificate contains a non-trusted ScribeRwKey.
	ErrDIDSCScribeKey = status.Error(codes.InvalidArgument, "bad DeviceIdScribeCertificate.ScribeRwKey")

	// ErrDIDSCScribeType indicates that the ScribeCertificate used to sign the DeviceIdScribeCertificate is not a Titan scribe key.
	ErrDIDSCScribeType = status.Error(codes.InvalidArgument, "bad ScribeCertificate.Magic")

	// ErrDIDSCSignature indicates that the DeviceIdScribeCertificate Signature does not validate using the ScribeCertificate public key.
	ErrDIDSCSignature = status.Error(codes.InvalidArgument, "DeviceIdScribeCertificate.Signature does not validate with ScribeCertificate public key")

	// ErrEKSignatureVersion indicates that the EkCertificate contains an invalid SignatureVersion.
	ErrEKSignatureVersion = status.Error(codes.InvalidArgument, "bad EkCertificate.SignatureVersion")

	// ErrEKSignaturePurpose indicates that the EkCertificate contains an invalid SignaturePurpose.
	ErrEKSignaturePurpose = status.Error(codes.InvalidArgument, "bad EkCertificate.SignaturePurpose")

	// ErrEKExtensionHeaderType indicates that the EkCertificate contains an invalid ExtensionHeaderType.
	ErrEKExtensionHeaderType = status.Error(codes.InvalidArgument, "bad EkCertificate.ExtensionHeaderType")

	// ErrEKKeyType indicates that the EkCertificate contains an invalid KeyType.
	ErrEKKeyType = status.Error(codes.InvalidArgument, "bad EkCertificate.KeyType")

	// ErrEKKeyOp indicates that the EkCertificate contains an invalid KeyOp.
	ErrEKKeyOp = status.Error(codes.InvalidArgument, "bad EkCertificate.KeyOp")

	// ErrEKKeyAlg indicates that the EkCertificate contains an invalid KeyAlg.
	ErrEKKeyAlg = status.Error(codes.InvalidArgument, "bad EkCertificate.KeyAlg")

	// ErrEKReserved0 indicates that the EkCertificate contains an invalid Reserved0.
	ErrEKReserved0 = status.Error(codes.InvalidArgument, "bad EkCertificate.Reserved0")

	// ErrEKPubKeySize indicates that the EkCertificate contains an invalid PubKeySize.
	ErrEKPubKeySize = status.Error(codes.InvalidArgument, "bad EkCertificate.PubKeySize")

	// ErrEKReserved1 indicates that the EkCertificate contains an invalid Reserved1.
	ErrEKReserved1 = status.Error(codes.InvalidArgument, "bad EkCertificate.Reserved1")

	// ErrEKHWCat indicates that the EkCertificate HwCat does not match the AliasKeyCertificate HwCat.
	ErrEKHWCat = status.Error(codes.InvalidArgument, "EkCertificate.HwCat does not match AliasKeyCertificate")

	// ErrEKHWID indicates that the EkCertificate HwId does not match the AliasKeyCertificate HwId.
	ErrEKHWID = status.Error(codes.InvalidArgument, "EkCertificate.HwId does not match AliasKeyCertificate")

	// ErrEKBootloaderTag indicates that the EkCertificate BootloaderTag does not match the AliasKeyCertificate BootloaderTag.
	ErrEKBootloaderTag = status.Error(codes.InvalidArgument, "EkCertificate.BootloaderTag does not match AliasKeyCertificate")

	// ErrEKFirmwareEpoch indicates that the EkCertificate FirmwareEpoch does not match the AliasKeyCertificate FirmwareEpoch.
	ErrEKFirmwareEpoch = status.Error(codes.InvalidArgument, "EkCertificate.FirmwareEpoch does not match AliasKeyCertificate")

	// ErrEKFirmwareMajorVersionMismatch indicates that the EkCertificate FirmwareMajorVersion does not match the AliasKeyCertificate FirmwareMajorVersion.
	ErrEKFirmwareMajorVersionMismatch = status.Error(codes.InvalidArgument, "EkCertificate.FirmwareMajorVersion does not match AliasKeyCertificate")

	// ErrEKFirmwareMajorVersionNonZero indicates that the EkCertificate FirmwareMajorVersion is non-zero.
	ErrEKFirmwareMajorVersionNonZero = status.Error(codes.InvalidArgument, "EkCertificate.FirmwareMajorVersion is non-zero.")

	// ErrEKPubToECCPoint indicates an error converting an EkCertificate's key to an ECC point.
	ErrEKPubToECCPoint = status.Error(codes.InvalidArgument, "error converting EkCertificate's public key to an ECC point")

	// ErrEKSignature indicates that the EkCertificate Signature does not validate using the AliasKeyCertificate.
	ErrEKSignature = status.Error(codes.InvalidArgument, "EkCertificate.Signature does not validate with AliasKeyCertificate")

	// ErrEKTemplate indicates that the EK template was incorrect.
	ErrEKTemplate = status.Error(codes.InvalidArgument, "EKCertificate object name does not match the expected template.")

	// ErrEKTemplateAssembly indicates that the EK certificate could not be assembled.
	ErrEKTemplateAssembly = status.Error(codes.Internal, "could not assemble EK certificate with expected template")
)
