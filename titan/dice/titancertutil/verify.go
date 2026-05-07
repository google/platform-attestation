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

package main

import (
	"fmt"
	"os"

	// Assuming these are the correct import paths
	"github.com/google/platform-attestation/titan/dice/scriberoots"
	"github.com/google/platform-attestation/titan/dice/titandice"
)

const (
	// ekCertChainNVIndex is the NVRAM index where the Endorsement Key
	// certificate chain is stored on the Titan device.
	ekCertChainNVIndex = 0x01c00100
)

var (
	// prodRwSigningKeyInfo represents the key information for the production
	// Read-Write firmware signing key.
	prodRwSigningKeyInfo = titandice.KeyInfo{0x47, 0x22, 0x4d, 0xc6}
)

// validateAndVerifyChain contains the core logic for validating a certificate chain byte slice.
func validateAndVerifyChain(certChainBytes []byte) error {
	roots, err := scriberoots.GetAllScribeRoots()
	if err != nil {
		return fmt.Errorf("getting embedded scribe roots: %w", err)
	}

	var rootCerts [][]byte
	for _, root := range roots {
		rootCerts = append(rootCerts, root)
	}

	opts := &titandice.ValidateScribeCertificateChainOptions{
		ScribeCertificates: rootCerts,
		RwSigningKeyInfos:  []titandice.KeyInfo{prodRwSigningKeyInfo},
	}
	validator, err := titandice.NewValidator(opts)
	if err != nil {
		return fmt.Errorf("creating validator: %w", err)
	}

	certChain, err := titandice.ParseTitanDiceScribeCertificateChain(certChainBytes)
	if err != nil {
		return fmt.Errorf("parsing certificate chain: %w", err)
	}

	if err := titandice.ValidateScribeCertificateChain(certChain, validator); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}

// verifyCertChainFromFile verifies the certificate chain read from the given file path.
func verifyCertChainFromFile(certChainPath string) error {
	certChainBytes, err := os.ReadFile(certChainPath)
	if err != nil {
		return fmt.Errorf("reading file %q: %w", certChainPath, err)
	}
	if err := validateAndVerifyChain(certChainBytes); err != nil {
		return fmt.Errorf("verifying chain from file %q: %w", certChainPath, err)
	}
	fmt.Println("Certificate chain from file is valid.")
	return nil
}
