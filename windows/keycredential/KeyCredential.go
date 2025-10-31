package keycredential

import (
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/crypto"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/key/customkeyinformation"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/key/source"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/key/usage"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/version"

	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/windows/guid"
)

// KeyCredential represents a key credential structure used for authentication and authorization.
//
// Fields:
// - Version: A KeyCredentialVersion object representing the version of the key credential.
// - Identifier: A string representing the unique identifier of the key credential.
// - KeyHash: A byte slice containing the hash of the key material.
// - RawKeyMaterial: An RSAKeyMaterial object representing the raw RSA key material.
// - Usage: A KeyUsage object representing the usage of the key credential.
// - LegacyUsage: A string representing the legacy usage of the key credential.
// - Source: A KeySource object representing the source of the key credential.
// - LastLogonTime: A DateTime object representing the last logon time associated with the key credential.
// - CreationTime: A DateTime object representing the creation time of the key credential.
// - Owner: A string representing the owner of the key credential.
// - RawBytes: A byte slice containing the raw binary data of the key credential.
// - RawBytesSize: A uint32 value representing the size of the raw binary data.
//
// Methods:
// - ParseDNWithBinary: Parses the provided DNWithBinary object into the KeyCredential structure.
//
// Note:
// The KeyCredential structure is used to store and manage key credentials, which are used for authentication and authorization purposes.
// The structure includes fields for version, identifier, key hash, raw key material, usage, legacy usage, source, last logon time, creation time, owner, and raw binary data.
// The ParseDNWithBinary method is used to parse a DNWithBinary object and populate the fields of the KeyCredential structure.
type KeyCredential struct {
	Version        version.KeyCredentialVersion
	Identifier     string
	KeyHash        []byte
	RawKeyMaterial crypto.RSAKeyMaterial
	Usage          usage.KeyUsage
	LegacyUsage    string
	Source         source.KeySource
	CustomKeyInfo  customkeyinformation.CustomKeyInformation
	DeviceId       guid.GUID
	LastLogonTime  utils.DateTime
	CreationTime   utils.DateTime

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// NewKeyCredential creates a new KeyCredential structure.
//
// Parameters:
//
// - version: A KeyCredentialVersion object representing the version of the key credential.
//
// - Identifier: A string representing the unique identifier of the key credential.
//
// - KeyHash: A byte slice containing the hash of the key material.
//
// - RawKeyMaterial: An RSAKeyMaterial object representing the raw RSA key material.
//
// - Usage: A KeyUsage object representing the usage of the key credential.
//
// - LegacyUsage: A string representing the legacy usage of the key credential.
//
// - Source: A KeySource object representing the source of the key credential.
//
// - CustomKeyInfo: A CustomKeyInformation object representing the custom key information of the key credential.
//
// - DeviceId: A GUID object representing the device ID of the key credential.
//
// - LastLogonTime: A DateTime object representing the last logon time associated with the key credential.
//
// - CreationTime: A DateTime object representing the creation time of the key credential.
//
// - Owner: A string representing the owner of the key credential.
//
// Returns:
//
// - A pointer to a KeyCredential object.
func NewKeyCredential(
	Version version.KeyCredentialVersion,
	Identifier string,
	RawKeyMaterial crypto.RSAKeyMaterial,
	DeviceId guid.GUID,
	LastLogonTime utils.DateTime,
	CreationTime utils.DateTime,
) *KeyCredential {
	kc := &KeyCredential{
		Version:        Version,
		Identifier:     Identifier,
		KeyHash:        []byte{},
		RawKeyMaterial: RawKeyMaterial,
		Usage:          usage.KeyUsage{Value: usage.KeyUsage_NGC},
		LegacyUsage:    "",
		Source:         source.KeySource{},
		CustomKeyInfo: customkeyinformation.CustomKeyInformation{
			Version: 1,
			Flags: customkeyinformation.CustomKeyInformationFlags{
				Value: 0,
			},
		},
		DeviceId:      DeviceId,
		LastLogonTime: LastLogonTime,
		CreationTime:  CreationTime,
		RawBytes:      []byte{},
		RawBytesSize:  0,
	}

	kc.Source.Value = source.KeySource_AD

	kc.KeyHash = kc.ComputeKeyHash()

	return kc
}

// ParseDNWithBinary parses the provided DNWithBinary object into the KeyCredential structure.
//
// Parameters:
// - dnWithBinary: A DNWithBinary object containing the distinguished name and binary data to be parsed.
//
// Returns:
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function performs the following steps:
// 1. Sets the RawBytes and RawBytesSize fields to the provided binary data and its length, respectively.
// 2. Sets the Owner field to the distinguished name from the DNWithBinary object.
// 3. Parses the version information from the binary data and updates the RawBytesSize and remainder accordingly.
// 4. Iterates through the remaining binary data, parsing each entry based on its type and length.
// 5. Updates the corresponding fields of the KeyCredential structure based on the parsed entry type and data.
//
// The function handles various entry types, including key identifier, key hash, key material, key usage, legacy usage, key source, last logon time, and creation time.
// Unsupported entry types, such as device ID and custom key information, are commented out for future implementation.
func (kc *KeyCredential) ParseDNWithBinary(dnWithBinary ldap.DNWithBinary) error {
	_, err := kc.Unmarshal(dnWithBinary.BinaryData)
	if err != nil {
		return err
	}
	return nil
}

// Unmarshal parses the provided binary data into the KeyCredential structure.
//
// Parameters:
// - data: A byte slice containing the binary data to be parsed.
//
// Returns:
// - bytesRead: The number of bytes read from the data.
// - error: An error if the parsing fails, otherwise nil.
//
// Note:
// The function performs the following steps:
// 1. Sets the RawBytes and RawBytesSize fields to the provided binary data and its length.
// 2. Parses the version information from the binary data.
// 3. Iterates through the remaining binary data, parsing each entry based on its type and length.
// 4. Updates the corresponding fields of the KeyCredential structure based on the parsed entry type and data.
//
// The function handles various entry types, including:
// - Key identifier
// - Key hash
// - Key material
// - Key usage (both V2 enum and legacy string formats)
// - Key source
// - Device ID
// - Custom key information
// - Last logon timestamp
// - Creation time
func (kc *KeyCredential) Unmarshal(data []byte) (int, error) {
	kc.RawBytes = data
	remainder := data
	bytesRead := 0 // This will track the total number of bytes successfully parsed and returned.

	// Unmarshal the KeyCredential version.
	// The version structure is responsible for parsing its own data and reporting its size.
	versionBytesRead, err := kc.Version.Unmarshal(remainder)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal KeyCredential version: %w", err)
	}
	bytesRead += versionBytesRead
	remainder = remainder[versionBytesRead:]

	// Iterate through the remaining data to parse all entries.
	// Each entry is structured as: [2 bytes: ValueLength] [1 byte: EntryType] [ValueLength bytes: ValueData].
	for len(remainder) > 0 {
		// Ensure there are enough bytes for the entry header (2 bytes for length + 1 byte for type).
		if len(remainder) < 3 {
			// If there are remaining bytes but not enough for a full header, the data is malformed.
			return bytesRead, fmt.Errorf("malformed KeyCredential: insufficient bytes for entry header (expected at least 3, got %d remaining)", len(remainder))
		}

		// Read the 16-bit little-endian length of the ValueData field.
		valueLength := binary.LittleEndian.Uint16(remainder[:2])

		// Extract the 1-byte EntryType. It is located at index 2 after the 2-byte length field.
		entryType := KeyCredentialEntryType{}
		// Assuming KeyCredentialEntryType.Unmarshal expects a 1-byte slice containing the type value.
		// The original code's `entryType.Unmarshal(remainder)` was likely incorrect as it would
		// attempt to parse the 2-byte length field as the entry type.
		_, err = entryType.Unmarshal(remainder[2:3])
		if err != nil {
			return bytesRead, fmt.Errorf("malformed KeyCredential: failed to unmarshal entry type: %w", err)
		}

		// Calculate the total size of the current entry:
		// 2 bytes (for valueLength) + 1 byte (for entryType) + valueLength bytes (for ValueData).
		totalEntrySize := 3 + int(valueLength)

		// Check if there are enough bytes in 'remainder' for the entire entry (header + value data).
		if len(remainder) < totalEntrySize {
			// This is the critical check to prevent "slice bounds out of range" panic.
			return bytesRead, fmt.Errorf("malformed KeyCredential: insufficient bytes for entry value data (expected %d bytes, got %d remaining)", totalEntrySize, len(remainder))
		}

		// Extract the ValueData field. It starts after the 2-byte length and 1-byte type.
		entryData := remainder[3:totalEntrySize]

		// Process the entry data based on its type.
		switch entryType.Value {
		case KeyCredentialEntryType_KeyID:
			kc.Identifier = utils.ConvertFromBinaryIdentifier(entryData, kc.Version)
		case KeyCredentialEntryType_KeyHash:
			kc.KeyHash = entryData
		case KeyCredentialEntryType_KeyMaterial:
			kc.RawKeyMaterial.FromBytes(entryData)
		case KeyCredentialEntryType_KeyUsage:
			if len(entryData) == 1 {
				// This is apparently a V2 structure (single byte enum).
				_, err := kc.Usage.Unmarshal(entryData)
				if err != nil {
					return bytesRead, fmt.Errorf("failed to unmarshal KeyCredential usage: %w", err)
				}
			} else {
				// This is a legacy structure that contains a string-encoded key usage.
				kc.LegacyUsage = string(entryData)
			}
		case KeyCredentialEntryType_KeySource:
			_, err := kc.Source.Unmarshal(entryData)
			if err != nil {
				return bytesRead, fmt.Errorf("failed to unmarshal KeyCredential source: %w", err)
			}
		case KeyCredentialEntryType_DeviceId:
			kc.DeviceId.FromRawBytes(entryData)
		case KeyCredentialEntryType_CustomKeyInformation:
			_, err := kc.CustomKeyInfo.Unmarshal(entryData, kc.Version)
			if err != nil {
				return bytesRead, fmt.Errorf("failed to unmarshal KeyCredential custom key information: %w", err)
			}
		case KeyCredentialEntryType_KeyApproximateLastLogonTimeStamp:
			kc.LastLogonTime = utils.ConvertFromBinaryTime(entryData, kc.Source, kc.Version)
		case KeyCredentialEntryType_KeyCreationTime:
			kc.CreationTime = utils.ConvertFromBinaryTime(entryData, kc.Source, kc.Version)
		}

		// Advance 'remainder' past the current entry and update 'bytesRead'.
		remainder = remainder[totalEntrySize:]
		bytesRead += totalEntrySize
	}

	// Update RawBytesSize with the total bytes successfully parsed.
	kc.RawBytesSize = uint32(bytesRead)
	return bytesRead, nil
}

// CheckIntegrity checks the integrity of the key credential.
//
// Returns:
// - A boolean value indicating the integrity of the key credential.
func (kc *KeyCredential) CheckIntegrity() bool {
	hash := kc.ComputeKeyHash()

	if len(hash) != len(kc.KeyHash) {
		return false
	}

	for i := range hash {
		if hash[i] != kc.KeyHash[i] {
			return false
		}
	}

	return true
}

// ComputeKeyHash computes the key hash of the key credential.
//
// Returns:
// - A byte slice containing the key hash.
func (kc *KeyCredential) ComputeKeyHash() []byte {
	// Src: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4f72-b7ef-8596013a36c7
	data := []byte{}

	if len(kc.RawBytes) < 4 {
		rawBytes, err := kc.Marshal()
		if err != nil {
			return nil
		}
		kc.RawBytes = rawBytes
	}

	remainder := kc.RawBytes[4:]

	// Read all entries corresponding to the KEYCREDENTIALLINK_ENTRY structure:
	for len(remainder) > 3 {
		// A 16-bit unsigned integer that specifies the length of the Value field.
		length := binary.LittleEndian.Uint16(remainder[:2])
		entryType := KeyCredentialEntryType{}
		_, err := entryType.Unmarshal(remainder)
		if err != nil {
			return nil
		}

		remainder = remainder[3:]
		remainder = remainder[length:]

		switch entryType.Value {
		case KeyCredentialEntryType_KeyHash:
			data = append(data, remainder...)
		}
	}

	hash := utils.ComputeHash(data)

	return hash
}

// Marshal returns the raw bytes of the KeyCredential structure.
//
// Returns:
// - A byte slice representing the raw bytes of the KeyCredential structure.
// - An error if the conversion fails.
func (kc *KeyCredential) Marshal() ([]byte, error) {
	var err error

	buffer := bytes.NewBuffer(nil)

	// kc.Version
	versionBytes, err := kc.Version.Marshal()
	if err != nil {
		return nil, err
	}
	buffer.Write(versionBytes)

	// kc.Identifier
	if len(kc.Identifier) > 0 {
		entryType := KeyCredentialEntryType{Value: KeyCredentialEntryType_KeyID}
		identifierBytes, err := utils.ConvertToBinaryIdentifier(kc.Identifier, kc.Version)
		if err != nil {
			return nil, err
		}
		WriteEntry(buffer, entryType, identifierBytes)
	}

	// kc.KeyHash
	if len(kc.KeyHash) > 0 {
		entryType := KeyCredentialEntryType{Value: KeyCredentialEntryType_KeyHash}
		WriteEntry(buffer, entryType, kc.KeyHash)
	} else {
		entryType := KeyCredentialEntryType{Value: KeyCredentialEntryType_KeyHash}
		WriteEntry(buffer, entryType, make([]byte, 32))
	}

	// kc.RawKeyMaterial
	entryType := KeyCredentialEntryType{Value: KeyCredentialEntryType_KeyMaterial}
	WriteEntry(buffer, entryType, kc.RawKeyMaterial.ToBytes())

	// kc.Usage
	entryType = KeyCredentialEntryType{Value: KeyCredentialEntryType_KeyUsage}
	WriteEntry(buffer, entryType, []byte{kc.Usage.Value})

	// kc.LegacyUsage
	if len(kc.LegacyUsage) > 0 {
		entryType = KeyCredentialEntryType{Value: KeyCredentialEntryType_KeyUsage}
		data := []byte(kc.LegacyUsage)
		WriteEntry(buffer, entryType, data)
	}

	// kc.Source
	entryType = KeyCredentialEntryType{Value: KeyCredentialEntryType_KeySource}
	data, err := kc.Source.Marshal()
	if err != nil {
		return nil, err
	}
	WriteEntry(buffer, entryType, data)

	// kc.DeviceId
	entryType = KeyCredentialEntryType{Value: KeyCredentialEntryType_DeviceId}
	WriteEntry(buffer, entryType, kc.DeviceId.ToBytes())

	// kc.CustomKeyInfo
	customKeyInfoBytes, err := kc.CustomKeyInfo.Marshal()
	if err != nil {
		return nil, err
	}
	if len(customKeyInfoBytes) > 0 {
		entryType := KeyCredentialEntryType{Value: KeyCredentialEntryType_CustomKeyInformation}
		WriteEntry(buffer, entryType, customKeyInfoBytes)
	}

	// kc.LastLogonTime
	entryType = KeyCredentialEntryType{Value: KeyCredentialEntryType_KeyApproximateLastLogonTimeStamp}
	data, err = kc.LastLogonTime.Marshal()
	if err != nil {
		return nil, err
	}
	WriteEntry(buffer, entryType, data)

	// kc.CreationTime
	entryType = KeyCredentialEntryType{Value: KeyCredentialEntryType_KeyCreationTime}
	data, err = kc.CreationTime.Marshal()
	if err != nil {
		return nil, err
	}
	WriteEntry(buffer, entryType, data)

	return buffer.Bytes(), nil
}

// Describe prints a detailed description of the KeyCredential structure.
//
// Parameters:
// - indent: An integer value specifying the indentation level for the output.
func (kc *KeyCredential) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<KeyCredential structure>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mVersion\x1b[0m: %s (0x%x)\n", indentPrompt, kc.Version.String(), kc.Version.Value)
	fmt.Printf("%s │ \x1b[93mKeyID\x1b[0m: %s\n", indentPrompt, kc.Identifier)
	if kc.CheckIntegrity() {
		fmt.Printf("%s │ \x1b[93mKeyHash\x1b[0m: %s (\x1b[92mvalid\x1b[0m)\n", indentPrompt, hex.EncodeToString(kc.KeyHash))
	} else {
		fmt.Printf("%s │ \x1b[93mKeyHash\x1b[0m: %s (\x1b[91minvalid\x1b[0m)\n", indentPrompt, hex.EncodeToString(kc.KeyHash))
	}
	kc.RawKeyMaterial.Describe(indent + 1)
	fmt.Printf("%s │ \x1b[93mUsage\x1b[0m: %s\n", indentPrompt, kc.Usage.String())
	if len(kc.LegacyUsage) != 0 {
		fmt.Printf("%s │ \x1b[93mLegacyUsage\x1b[0m: %s\n", indentPrompt, kc.LegacyUsage)
	} else {
		fmt.Printf("%s │ \x1b[93mLegacyUsage\x1b[0m: None\n", indentPrompt)
	}
	fmt.Printf("%s │ \x1b[93mSource\x1b[0m: 0x%02x (%s)\n", indentPrompt, kc.Source.Value, kc.Source.String())
	fmt.Printf("%s │ \x1b[93mDeviceId\x1b[0m: %s\n", indentPrompt, kc.DeviceId.ToFormatD())
	kc.CustomKeyInfo.Describe(indent + 1)
	fmt.Printf("%s │ \x1b[93mLastLogonTime (UTC)\x1b[0m: %s\n", indentPrompt, kc.LastLogonTime.String())
	fmt.Printf("%s │ \x1b[93mCreationTime (UTC)\x1b[0m: %s\n", indentPrompt, kc.CreationTime.String())
	fmt.Printf("%s └───\n", indentPrompt)
}
