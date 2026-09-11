package measurements

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	apb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-tpm/tpm2"
)

var expectedWarmResetNVPublic = tpm2.TPMSNVPublic{
	NVIndex:    tpm2.TPMIRHNVIndex(warmResetHandle),
	NameAlg:    warmResetHash,
	DataSize:   warmResetSize,
	Attributes: expectedNVAttributes,
}

var nvCmpOpts = []cmp.Option{cmpopts.IgnoreUnexported(tpm2.TPMSNVPublic{}, tpm2.TPMANV{}, tpm2.TPMSNVCertifyInfo{}, tpm2.TPM2BName{}, tpm2.TPM2BData{}, tpm2.TPM2BDigest{}, tpm2.TPMSAttest{}, tpm2.TPMUAttest{}, tpm2.TPMTSignature{}, tpm2.TPMUSignature{}, tpm2.TPMSSignatureECC{}, tpm2.TPM2BECCParameter{}), cmpopts.EquateEmpty()}

func TestNVPublicName(t *testing.T) {
	expected := expectedWarmResetNVPublic
	publicBytes := tpm2.Marshal(&expected)

	name, err := cpuWarmResetNvPublicName(publicBytes)
	if err != nil {
		t.Fatalf("cpuWarmResetNvPublicName failed: %v", err)
	}

	expectedName, err := tpm2.NVName(&expected)
	if err != nil {
		t.Fatalf("tpm2.NVName failed: %v", err)
	}

	if !cmp.Equal(name, expectedName, nvCmpOpts...) {
		t.Errorf("got name %v, want %v", name, expectedName)
	}
}

func TestNVPublicNameErrors(t *testing.T) {
	testcases := []struct {
		name        string
		publicBytes []byte
		wantErr     string
	}{
		{
			name:        "unmarshal error",
			publicBytes: []byte{0xff},
			wantErr:     "failed to unmarshal NV public",
		},
		{
			name:        "mismatch index error",
			publicBytes: tpm2.Marshal(&tpm2.TPMSNVPublic{NVIndex: tpm2.TPMIRHNVIndex(0x1234)}),
			wantErr:     "NV index 4660 does not match expected index 29425669",
		},
		{
			name: "mismatch attributes error",
			publicBytes: tpm2.Marshal(&tpm2.TPMSNVPublic{
				NVIndex:    tpm2.TPMIRHNVIndex(warmResetHandle),
				NameAlg:    warmResetHash,
				DataSize:   warmResetSize,
				Attributes: tpm2.TPMANV{Written: true}, // Missing many attributes.
			}),
			wantErr: "NV attributes",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cpuWarmResetNvPublicName(tc.publicBytes)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got error %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestExtractNV(t *testing.T) {
	nonce := []byte("testnonce")
	nvInfo := tpm2.TPMSNVCertifyInfo{
		IndexName:  tpm2.TPM2BName{Buffer: []byte("testname")},
		NVContents: tpm2.TPM2BData{Buffer: []byte("testcontent")},
	}
	attest := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestNV,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested:  tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nvInfo),
	}
	attestBytes := tpm2.Marshal(&attest)

	got, err := extractCpuWarmResetNV(attestBytes, nonce)
	if err != nil {
		t.Fatalf("extractCpuWarmResetNV failed: %v", err)
	}

	if !cmp.Equal(got, &nvInfo, nvCmpOpts...) {
		t.Errorf("got %v, want %v", got, nvInfo)
	}
}

func TestExtractNVErrors(t *testing.T) {
	nonce := []byte("testnonce")
	testcases := []struct {
		name       string
		tpmsattest []byte
		nonce      []byte
		wantErr    string
	}{
		{
			name:       "unmarshal error",
			tpmsattest: []byte{0xff},
			wantErr:    "failed to unmarshal attestation",
		},
		{
			name: "wrong type",
			tpmsattest: tpm2.Marshal(&tpm2.TPMSAttest{
				Magic: tpm2.TPMGeneratedValue,
				Type:  tpm2.TPMSTAttestCertify,
			}),
			wantErr: "wrong CertifyNV attestation type",
		},
		{
			name: "wrong magic",
			tpmsattest: tpm2.Marshal(&tpm2.TPMSAttest{
				Magic: 0x12345678,
				Type:  tpm2.TPMSTAttestNV,
			}),
			wantErr: "wrong magic value",
		},
		{
			name: "nonce mismatch",
			tpmsattest: tpm2.Marshal(&tpm2.TPMSAttest{
				Magic:     tpm2.TPMGeneratedValue,
				Type:      tpm2.TPMSTAttestNV,
				ExtraData: tpm2.TPM2BData{Buffer: []byte("wrong")},
			}),
			nonce:   nonce,
			wantErr: "extra data does not match nonce",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractCpuWarmResetNV(tc.tpmsattest, tc.nonce)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got error %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyNVSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("testdata")
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	sig := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
		}),
	}
	sigBytes := tpm2.Marshal(&sig)

	certify := &apb.TpmAuxiliaryAttestation_SignedNvCertify{
		TpmsAttest:    data,
		TpmtSignature: sigBytes,
	}

	if err := verifySig(certify, &priv.PublicKey); err != nil {
		t.Errorf("verifySig failed: %v", err)
	}
}

func TestVerifyNVSignatureErrors(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := []byte("testdata")

	testcases := []struct {
		name    string
		certify *apb.TpmAuxiliaryAttestation_SignedNvCertify
		ak      crypto.PublicKey
		wantErr string
	}{
		{
			name:    "invalid AK type",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{},
			ak:      nil,
			wantErr: "invalid AK type",
		},
		{
			name: "unmarshal signature error",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmtSignature: []byte{0xff},
			},
			ak:      &priv.PublicKey,
			wantErr: "failed to unmarshal signature",
		},
		{
			name: "not ECDSA signature",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmtSignature: tpm2.Marshal(&tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgRSASSA}),
			},
			ak:      &priv.PublicKey,
			wantErr: "failed to get ECDSA member",
		},
		{
			name: "unsupported hash",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmsAttest: data,
				TpmtSignature: tpm2.Marshal(&tpm2.TPMTSignature{
					SigAlg: tpm2.TPMAlgECDSA,
					Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
						Hash: tpm2.TPMAlgSHA1,
					}),
				}),
			},
			ak:      &priv.PublicKey,
			wantErr: "only SHA256 is supported",
		},
		{
			name: "verification failure",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmsAttest: data,
				TpmtSignature: tpm2.Marshal(&tpm2.TPMTSignature{
					SigAlg: tpm2.TPMAlgECDSA,
					Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
						Hash:       tpm2.TPMAlgSHA256,
						SignatureR: tpm2.TPM2BECCParameter{Buffer: []byte("bad")},
						SignatureS: tpm2.TPM2BECCParameter{Buffer: []byte("bad")},
					}),
				}),
			},
			ak:      &priv.PublicKey,
			wantErr: "failed to verify ECDSA signature",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifySig(tc.certify, tc.ak)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got error %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestExtractWarmResetCount(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce := []byte("testnonce")
	expectedCount := int64(42)

	// Construct NV contents.
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, expectedCount)
	nvContents := buf.Bytes()

	// Get expected name.
	expectedPublic := expectedWarmResetNVPublic
	expectedName, err := tpm2.NVName(&expectedPublic)
	if err != nil {
		t.Fatalf("tpm2.NVName failed: %v", err)
	}

	// Construct NV Info.
	nvInfo := tpm2.TPMSNVCertifyInfo{
		IndexName:  *expectedName,
		Offset:     warmResetOffset,
		NVContents: tpm2.TPM2BData{Buffer: nvContents},
	}

	// Construct Attestation.
	attest := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestNV,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested:  tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nvInfo),
	}
	attestBytes := tpm2.Marshal(&attest)

	// Construct Signature.
	hash := sha256.Sum256(attestBytes)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	sig := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
		}),
	}
	sigBytes := tpm2.Marshal(&sig)

	certify := &apb.TpmAuxiliaryAttestation_SignedNvCertify{
		TpmsAttest:    attestBytes,
		TpmtSignature: sigBytes,
		TpmsNvPublic:  tpm2.Marshal(&expectedPublic),
	}

	got, err := VerifyWarmResetNVIndex(certify, nonce, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyWarmResetNVIndex failed: %v", err)
	}

	if got != expectedCount {
		t.Errorf("got count %v, want %v", got, expectedCount)
	}
}

func TestExtractWarmResetCountErrors(t *testing.T) {
	nonce := []byte("testnonce")
	expectedCount := int64(42)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, expectedCount)
	nvContents := buf.Bytes()
	expectedPublic := expectedWarmResetNVPublic
	expectedName, _ := tpm2.NVName(&expectedPublic)

	// Create test NV Info and Attestation.
	nvInfo := tpm2.TPMSNVCertifyInfo{
		IndexName:  *expectedName,
		Offset:     warmResetOffset,
		NVContents: tpm2.TPM2BData{Buffer: nvContents},
	}
	attest := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestNV,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested:  tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nvInfo),
	}
	attestBytes := tpm2.Marshal(&attest)
	hash := sha256.Sum256(attestBytes)

	// Create signature.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
	sig := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
		}),
	}
	sigBytes := tpm2.Marshal(&sig)
	nvPublicBytes := tpm2.Marshal(&expectedPublic)

	testcases := []struct {
		name    string
		certify *apb.TpmAuxiliaryAttestation_SignedNvCertify
		nonce   []byte
		ak      crypto.PublicKey
		wantErr string
	}{
		{
			name:    "nil certify",
			certify: nil,
			wantErr: "NV certification is nil",
		},
		{
			name: "signature verification failure",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmsAttest:    attestBytes,
				TpmtSignature: []byte("bad"),
			},
			nonce:   nonce,
			ak:      &priv.PublicKey,
			wantErr: "failed to verify NV signature",
		},
		{
			name: "extraction failure (wrong nonce)",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmsAttest:    attestBytes,
				TpmtSignature: sigBytes,
			},
			nonce:   []byte("wrong"),
			ak:      &priv.PublicKey,
			wantErr: "failed to extract NV",
		},
		{
			name: "NV public name mismatch",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmsAttest:    attestBytes,
				TpmtSignature: sigBytes,
				TpmsNvPublic:  tpm2.Marshal(&tpm2.TPMSNVPublic{NVIndex: tpm2.TPMIRHNVIndex(0x1234)}),
			},
			nonce:   nonce,
			ak:      &priv.PublicKey,
			wantErr: "failed to get NV public name",
		},
		{
			name: "Index name mismatch",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmsAttest: func() []byte {
					a := attest
					nv := nvInfo
					nv.IndexName = tpm2.TPM2BName{Buffer: []byte("wrong")}
					a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nv)
					return tpm2.Marshal(&a)
				}(),
				TpmtSignature: func() []byte {
					a := attest
					nv := nvInfo
					nv.IndexName = tpm2.TPM2BName{Buffer: []byte("wrong")}
					a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nv)
					ab := tpm2.Marshal(&a)
					h := sha256.Sum256(ab)
					r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
					sig := tpm2.TPMTSignature{
						SigAlg: tpm2.TPMAlgECDSA,
						Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
							Hash:       tpm2.TPMAlgSHA256,
							SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
							SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
						}),
					}
					return tpm2.Marshal(&sig)
				}(),
				TpmsNvPublic: nvPublicBytes,
			},
			nonce:   nonce,
			ak:      &priv.PublicKey,
			wantErr: "NV name [119 114 111 110 103] does not match expected name",
		},
		{
			name: "Offset mismatch",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmsAttest: func() []byte {
					a := attest
					nv := nvInfo
					nv.Offset = 1
					a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nv)
					return tpm2.Marshal(&a)
				}(),
				TpmtSignature: func() []byte {
					a := attest
					nv := nvInfo
					nv.Offset = 1
					a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nv)
					ab := tpm2.Marshal(&a)
					h := sha256.Sum256(ab)
					r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
					sig := tpm2.TPMTSignature{
						SigAlg: tpm2.TPMAlgECDSA,
						Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
							Hash:       tpm2.TPMAlgSHA256,
							SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
							SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
						}),
					}
					return tpm2.Marshal(&sig)
				}(),
				TpmsNvPublic: nvPublicBytes,
			},
			nonce:   nonce,
			ak:      &priv.PublicKey,
			wantErr: "NV offset 1 does not match expected offset 0",
		},
		{
			name: "Size mismatch",
			certify: &apb.TpmAuxiliaryAttestation_SignedNvCertify{
				TpmsAttest: func() []byte {
					a := attest
					nv := nvInfo
					nv.NVContents.Buffer = []byte{1, 2, 3}
					a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nv)
					return tpm2.Marshal(&a)
				}(),
				TpmtSignature: func() []byte {
					a := attest
					nv := nvInfo
					nv.NVContents.Buffer = []byte{1, 2, 3}
					a.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestNV, &nv)
					ab := tpm2.Marshal(&a)
					h := sha256.Sum256(ab)
					r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
					sig := tpm2.TPMTSignature{
						SigAlg: tpm2.TPMAlgECDSA,
						Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
							Hash:       tpm2.TPMAlgSHA256,
							SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
							SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
						}),
					}
					return tpm2.Marshal(&sig)
				}(),
				TpmsNvPublic: nvPublicBytes,
			},
			nonce:   nonce,
			ak:      &priv.PublicKey,
			wantErr: "NV data length 3 does not match expected length 8",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyWarmResetNVIndex(tc.certify, tc.nonce, tc.ak)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got error %v, want %v", err, tc.wantErr)
			}
		})
	}
}
