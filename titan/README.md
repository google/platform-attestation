# Titan Root of Trust

This folder contains information to validate the certificates of a Google Titan
root of trust.

## Information about the Titan RoT

### Boot Stages

The Titan Root of Trust consists of 3 stages:

1. Immutable ROM
2. Mutable Bootloader
3. Mutable Application Firmware

Each stage launches the next stage in the list.

### TPM Certificate Chain

The Titan TPM certificate chain consists of the following keys/certificates:

1.  Google Root CA Keys
2.  DICE Device ID Certificate
3.  DICE Alias Key Certificate
4.  TPM Firmware-limited EK (FEK) Certificate

Each certificate in the chain is signed by the key corresponding to the
certificate in the item above.

```
Google Root CA Key -> DICE Device ID Key -> DICE Alias Key -> TPM FEK
```

## Certificate Details

### Types

All types used in Titan certificates are little-endian. The table below lists
common types used throughout the certificates.

| **Name**   | **Size** | **Description**
| ---------- | -------- | ----------------------------------------------------
| `U8`       | 1        | 1-byte unsigned integer.
| `U16`      | 2        | 2-byte little-endian unsigned integer.
| `U32`      | 4        | 4-byte little-endian unsigned integer.
| `U64`      | 8        | 8-byte little-endian unsigned integer.
| `SHA256`   | 32       | A SHA256 hash, stored in little-endian byte order.
| `P256_INT` | 32       | A P256 integer, stored in little-endian byte order. Used for ECDSA public key points (x,y) and signature components (r,s).
| `BYTES[X]` | Variable | An arbitrary sequence of little-endian bytes of length X. Constant-value instances may be denoted as, `[<value>, <length>]`.

### Named Fields

Certain fields in the certificates carry specific meanings. These fields are
described below.

#### Key ID and Key Info

Key ID and Key Info are truncated prefixes of the SHA256 hash of the `x` and `y`
coordinates of a public key, `SHA256(x || y)`.

*   A Key Info is the first 4 bytes of the hash
*   A Key ID is the first 16 bytes of the hash

#### Firmware Hash

The firmware hash is a measurement of the signature structure of the application
firmware, not the entire firmware binary itself. This signature structure
includes hashes of all the non-volatile regions of the application firmware,
thereby preserving integrity of the entire firmware binary.

#### Hardware Category

The hardware category represents the type of Titan hardware. The following
values are valid: `[1, 4]`.

#### Bootloader Tag

The bootloader tag is a value associated with the version of booloader firmware
running on the Titan RoT. The following values are valid:
`[0x150F0001, 0x04970204]`.

#### Application Firmware Key Info

The application firmware key info is the identity of the code signing key used
to sign application firmware. The following values are valid:
`[0x5816db93, 0xc64d2247]`.

#### Qualified Name

The Qualified Name used within the TPM Firmware-limited EK (FEK) Certificate is
calculated as specified in the
[TPM Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
(See Qualified Name in Part 1: Architecture). Because the FEK is a primary key,
it is specifically computed as the following:

```
qualified_name = SHA256(TPM_RH_FW_ENDORSEMENT || NAME_FEK)
```

where `TPM_RH_FW_ENDORSEMENT` is the constant `0x40000141` and `NAME_FEK` is the
name of the TPM-held key. `NAME_FEK` is also calculated as specified in the TPM
Specification (See Names in Part 1: Architecture). It is specifically computed
as the following:

```
NAME_FEK = TPM_ALG_SHA256 || SHA256(FEK_PUBLIC_TEMPLATE)
```

where `TPM_ALG_SHA256` is the constant `0x000B` and `FEK_PUBLIC_TEMPLATE` is the
template used to create the TPM FEK. The template is retrieved from the NV Index
specified in the
[TCG EK Credential Profile](https://trustedcomputinggroup.org/resource/http-trustedcomputinggroup-org-wp-content-uploads-tcg-ek-credential-profile-v-2-5-r2_published-pdf/)
(NV Index `0x01c00056`).

### Combinations of allowed values in named fields

There are two distinct generations of Titan RoTs. Each generation has specific
requirements on the combination of Hardware Category, Bootloader Tag, and
Application firmware Key Info:

| **Generation** | **HW Category** | **Bootloader Tag** | **Application Firmware Key Info**
| -------------- | --------------- | ------------------ | ---------------------------------
| 1              | `1`             | `0x150f0001`       | `0x5816db93`
| 2              | `4`             | `0x04970204`       | `0xc64d2247`

Mixing acceptable values between generations is not valid.

### Certificate formats

#### Google Root CA Keys

Google maintains Root CA keys authorized to sign DICE Device ID Certificates for
Titan root of trust devices. The set of Root CA public keys is in `TBD`.

#### DICE Device ID Certificate

| **Byte Offset** | **Type**    | **Name**       | **Description**
| --------------- | ----------- | -------------- | ----------------------------
| 0x00            | `U32`       | Version        | Constant value `1`
| 0x04            | `U32`       | Purpose        | Constant value `9`
| 0x08            | `U8`        | Extension Type | Constant value `0`
| 0x09            | `U8`        | Key Type       | Constant value `5`
| 0x0A            | `U8`        | Key Operation  | Constant value `0`
| 0x0B            | `U8`        | Key Algorithm  | Constant value `0`
| 0x0C            | `U32`       | Key Info       | A trusted Google Root CA Key
| 0x10            | `BYTES[16]` | Validity       | Constant value `[0x0, 16]`
| 0x20            | `BYTES[16]` | Key ID         | A trusted Google Root CA Key
| 0x30            | `U64`       | HW ID          | Unique ID of the Titan RoT
| 0x38            | `U16`       | HW Category    | Category of the Titan RoT
| 0x3A            | `U16`       | Size           | Constant value `128`
| 0x3C            | `U32`       | Bootloader Tag | Tag of bootloader firmware
| 0x40            | `P256_INT`  | Public Key x   | ECP256 Public Key x component
| 0x60            | `P256_INT`  | Public Key y   | ECP256 Public Key y component
| 0x80            | `P256_INT`  | Signature r    | ECDSA Signature r component
| 0xA0            | `P256_INT`  | Signature s    | ECDSA Signature s component

Total size: 0xC0 (192)

#### DICE Alias Key Certificate

| **Byte Offset** | **Type**    | **Name**       | **Description**
| --------------- | ----------- | -------------- | ----------------------------
| 0x00            | `U32`       | Version        | Constant value `1`
| 0x04            | `U32`       | Purpose        | Constant value `11`
| 0x08            | `U8`        | Extension Type | Constant value `2`
| 0x09            | `U8`        | Key Type       | Constant value `6`
| 0x0A            | `U8`        | Key Operation  | Constant value `0`
| 0x0B            | `U8`        | Key Algorithm  | Constant value `0`
| 0x0C            | `U32`       | Key Info       | DICE Device ID Key Info
| 0x10            | `U32`       | Sign Key Info  | Application firmware Key Info
| 0x14            | `BYTES[12]` | Validity       | Constant value `[0x0, 12]`
| 0x20            | `U64`       | HW ID          | Unique ID of the Titan RoT
| 0x28            | `U16`       | HW Category    | Category of the Titan RoT
| 0x2A            | `BYTES[2]`  | Reserved 0     | Constant value `[0x0, 2]`
| 0x2C            | `U32`       | Bootloader Tag | Tag of bootloader firmware
| 0x30            | `U32`       | Firmware Epoch | Epoch version number of application firmware
| 0x34            | `U16`       | SVN            | Security version number of application firmware
| 0x36            | `U16`       | Size           | Constant value `64`
| 0x38            | `BYTES[8]`  | Reserved 1     | Constant value `[0x0, 8]`
| 0x40            | `P256_INT`  | Public Key x   | ECP256 Public Key x component
| 0x60            | `P256_INT`  | Public Key y   | ECP256 Public Key y component
| 0x80            | `P256_INT`  | Signature r    | ECDSA Signature r component
| 0xA0            | `P256_INT`  | Signature s    | ECDSA Signature s component
| 0xC0            | `SHA256`    | Firmware Hash  | Application firmware hash

Total size: 0xE0 (224)

#### TPM Firmware-limited EK (FEK) Certificate

| **Byte Offset** | **Type**    | **Name**       | **Description**
| --------------- | ----------- | -------------- | ----------------------------
| 0x00            | `U32`       | Version        | Constant value `1`
| 0x04            | `U32`       | Purpose        | Constant value `1`
| 0x08            | `U8`        | Extension Type | Constant value `0`
| 0x09            | `U8`        | Key Type       | Constant value `8`
| 0x0A            | `U8`        | Key Operation  | Constant value `0`
| 0x0B            | `U8`        | Key Algorithm  | Constant value `0`
| 0x0C            | `U32`       | Key Info       | DICE Alias Key Info
| 0x10            | `U32`       | FEK Key Info   | TPM FEK Key Info
| 0x14            | `BYTES[12]` | Validity       | Constant value `[0x0, 12]`
| 0x20            | `U64`       | HW ID          | Unique ID of the Titan RoT
| 0x28            | `U16`       | HW Category    | Category of the Titan RoT
| 0x2A            | `BYTES[2]`  | Reserved 0     | Constant value `[0x0, 2]`
| 0x2C            | `U32`       | Bootloader Tag | Tag of bootloader firmware
| 0x30            | `U32`       | Firmware Epoch | Epoch version number of application firmware
| 0x34            | `U16`       | SVN            | Security version number of application firmware
| 0x36            | `U16`       | Size           | Constant value `64`
| 0x38            | `BYTES[8]`  | Reserved 1     | Constant value `[0x0, 8]`
| 0x40            | `SHA256`    | Firmware Hash  | Application firmware hash
| 0x60            | `SHA256`    | Qualified Name | Qualified name of FEK object in TPM
| 0x80            | `P256_INT`  | Public Key x   | ECP256 Public Key x component
| 0xA0            | `P256_INT`  | Public Key y   | ECP256 Public Key y component
| 0xC0            | `P256_INT`  | Signature r    | ECDSA Signature r component
| 0xE0            | `P256_INT`  | Signature s    | ECDSA Signature s component

Total size: 0x100 (256)
