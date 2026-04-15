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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func parseAliasKeyCertificate(r io.Reader) (*AliasKeyCertificate, error) {
	var akc AliasKeyCertificate
	if err := binary.Read(r, binary.LittleEndian, &akc.Header); err != nil {
		return nil, fmt.Errorf("failed to read AliasKeyCertificate header: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &akc.PublicKey); err != nil {
		return nil, fmt.Errorf("failed to read AliasKeyCertificate public key: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &akc.Signature); err != nil {
		return nil, fmt.Errorf("failed to read AliasKeyCertificate signature: %w", err)
	}
	if akc.Header.ExtensionHeaderType == SigExtensionHeaderTypeFirmwareHash {
		if err := binary.Read(r, binary.LittleEndian, &akc.FWHash); err != nil {
			return nil, fmt.Errorf("failed to read AliasKeyCertificate FWHash: %w", err)
		}
	}
	return &akc, nil
}

func parseDeviceIDCertificate(r io.Reader) (*DeviceIDCertificate, error) {
	var didc DeviceIDCertificate
	if err := binary.Read(r, binary.LittleEndian, &didc.Header); err != nil {
		return nil, fmt.Errorf("failed to read DeviceIDCertificate header: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &didc.Key); err != nil {
		return nil, fmt.Errorf("failed to read DeviceIDCertificate key: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &didc.Signature); err != nil {
		return nil, fmt.Errorf("failed to read DeviceIDCertificate signature: %w", err)
	}
	return &didc, nil
}

func parseDeviceIDScribeCertificate(r io.Reader) (*DeviceIDScribeCertificate, error) {
	var didsc DeviceIDScribeCertificate
	if err := binary.Read(r, binary.LittleEndian, &didsc); err != nil {
		return nil, fmt.Errorf("failed to read DeviceIDScribeCertificate: %w", err)
	}
	return &didsc, nil
}

// ParseTitanDiceScribeCertificateChain parses a byte slice into a TitanDiceScribeCertificateChain.
// The byte slice is expected to contain the AliasKeyCertificate, followed by the
// DeviceIDCertificate, and finally the DeviceIDScribeCertificate.
func ParseTitanDiceScribeCertificateChain(data []byte) (*TitanDiceScribeCertificateChain, error) {
	r := bytes.NewReader(data)

	akc, err := parseAliasKeyCertificate(r)
	if err != nil {
		return nil, err
	}

	didc, err := parseDeviceIDCertificate(r)
	if err != nil {
		return nil, err
	}

	didsc, err := parseDeviceIDScribeCertificate(r)
	if err != nil {
		return nil, err
	}

	return &TitanDiceScribeCertificateChain{
		AliasKeyCertificate:       *akc,
		DeviceIDCertificate:       *didc,
		DeviceIDScribeCertificate: *didsc,
	}, nil
}
