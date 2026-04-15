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
	"crypto/sha256"
	"fmt"
)

// Titan measures descriptor hashes into different PCRs depending on the
// device being measured.
//
// * PCR0: For Target ASIC (directly connected to & measured by the Titan)
// * PCR17: For a secondary device measured by the Target ASIC (e.g. CPU FW, measured by BMC)
const (
	sHrtmPcrIndex uint32 = 0
	drtmPcrIndex  uint32 = 17
	NumPCRs              = 24
)

// PCR represents a single PCR register.
type PCR struct {
	Index  int
	Digest []byte
}

// VirtualTPM represents a virtual TPM with a bank of PCRs.
type PCRBank struct {
	PCRs [NumPCRs]PCR
}

// New creates and initializes a new VirtualTPM.
func NewPCRBank() *PCRBank {
	pb := &PCRBank{}
	for i := 0; i < NumPCRs; i++ {
		digest := make([]byte, sha256.Size)
		// Initialize PCRs 17-22 with 0xff bytes as defined in TCG PC Client
		// profile
		if i >= 17 && i <= 22 {
			for j := 0; j < sha256.Size; j++ {
				digest[j] = 0xff
			}
		}
		pb.PCRs[i] = PCR{
			Index:  i,
			Digest: digest,
		}
	}
	return pb
}

// Extend simulates a PCR extension.
func (pb *PCRBank) Extend(pcrIndex int, data []byte) error {
	if pcrIndex < 0 || pcrIndex >= NumPCRs {
		return fmt.Errorf("invalid PCR index: %d", pcrIndex)
	}

	pcr := &pb.PCRs[pcrIndex]
	hasher := sha256.New()
	hasher.Write(pcr.Digest)
	hasher.Write(data)
	pcr.Digest = hasher.Sum(nil)

	return nil
}

func (pb *PCRBank) Event(pcrIndex int, data []byte) error {
	hasher := sha256.New()
	hasher.Write(data)

	return pb.Extend(pcrIndex, hasher.Sum(nil))
}

// PerformSHRTM initializes PCR0 to a state representing 0x4 and then extends it with the provided measurement.
func (pb *PCRBank) PerformSHRTM(measurementData []byte) error {
	// Initialize PCR0 big-endian 0x04.
	// This simulates a specific initial measurement for S-HRTM. In Titan,
	// S-HRTM is always performed from locality 4, so the PCR is first initialized
	// with that locality.
	pb.PCRs[sHrtmPcrIndex].Digest = make([]byte, sha256.Size)
	pb.PCRs[sHrtmPcrIndex].Digest[sha256.Size-1] = 0x4

	hasher := sha256.New()
	hasher.Write(measurementData)

	// Then, extend PCR0 with the actual measurement data.
	return pb.Extend(int(sHrtmPcrIndex), hasher.Sum(nil))
}

func (pb *PCRBank) PerformDRTM(measurementData []byte) error {
	// Initialize PCR17 big-endian zeros.
	// This simulates a specific initial measurement for DRTM.
	// On Titan, all DRTM measurements are executed from
	// locality 0.
	pb.PCRs[drtmPcrIndex].Digest = make([]byte, sha256.Size)

	hasher := sha256.New()
	hasher.Write(measurementData)

	// Then, extend PCR0 with the actual measurement data.
	return pb.Extend(int(drtmPcrIndex), hasher.Sum(nil))
}

// String returns a string representation of the PCRBank.
func (pb *PCRBank) String() string {
	s := "PCRBank:\n"
	for i := 0; i < NumPCRs; i++ {
		s += fmt.Sprintf("  PCR %d: %x\n", pb.PCRs[i].Index, pb.PCRs[i].Digest)
	}
	return s
}
