# Titan v3 DICE

Google's Titan v3 RoT chips implement DICE and the TPM API surface. The DICE
flow is as follows:

* Each Titan chip has two unique certificates that identify the hardware.
  Each is signed by an HSM ("Scribe") during chip manufacturing. These
  certificates cover a hardware DeviceID key.
  * `DeviceIdCertificate`
  * `DeviceIdScribeCertificate`
* Titan FW bootloader measures Titan application firmware and derives
  an AliasKey based on those measurements. The AliasKeyCertificate is signed by
  `DeviceID_priv`. This certificate is generated and signed by the bootloader.
* Titan Application firmware generates two TPM identiy certificates, both
  signed by `AliasKey_priv`
  * `EkCertificate`: Derived from the TPM Endorsement Primary Seed, based on
    hardware identity.
  * `FekCertificate`: Derived from the TPM Firmware Endorsement Primary Seed
    (FEPS). FEPS is derived with `KDF(EPS, titan_fw_hash)`.
