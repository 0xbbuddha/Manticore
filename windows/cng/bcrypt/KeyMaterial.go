package bcrypt

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/magic"
)

// KeyMaterial is an interface that represents a key material in memory.
//
// It provides methods for unmarshalling, marshalling, and comparing key materials.
type KeyMaterial interface {
	Unmarshal(data []byte) (int, error)
	Marshal() ([]byte, error)
	Describe(indent int)
}

// UnmarshalKeyMaterial unmarshals the key material from the provided byte slice.
//
// Parameters:
// - data: A byte slice containing the raw key material to be parsed.
//
// Returns:
// - A KeyMaterial object representing the key material.
// - An error if the unmarshalling fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the key material format, starting with the "KEY1" blob type identifier.
// It extracts the key type from the byte slice and stores it in the BCRYPT_KEY_BLOB structure.
func UnmarshalKeyMaterial(data []byte) (KeyMaterial, int, error) {
	blobMagic := magic.BCRYPT_KEY_BLOB{}
	_, err := blobMagic.Unmarshal(data)
	if err != nil {
		return nil, 0, err
	}

	switch blobMagic.Magic {

	case magic.BCRYPT_RSAPUBLIC_MAGIC:
		blob := keys.BCRYPT_RSA_PUBLIC_KEY{}
		bytesRead, err := blob.Unmarshal(data)
		if err != nil {
			return nil, 0, err
		}
		return &blob, bytesRead, nil

	case magic.BCRYPT_RSAPRIVATE_MAGIC:
		blob := keys.BCRYPT_RSA_PRIVATE_KEY{}
		bytesRead, err := blob.Unmarshal(data)
		if err != nil {
			return nil, 0, err
		}
		return &blob, bytesRead, nil
		// case magic.BCRYPT_ECCPUBLIC_MAGIC:
		// 	blob := keys.BCRYPT_ECC_PUBLIC_KEY{}
		// 	bytesRead, err := blob.Unmarshal(data)
		// 	if err != nil {
		// 		return nil, 0, err
		// 	}
		// 	return &blob, bytesRead, nil
		// case magic.BCRYPT_ECCPRIVATE_MAGIC:
		// 	blob := keys.BCRYPT_ECC_PRIVATE_KEY{}
		// 	bytesRead, err := blob.Unmarshal(data)
		// 	if err != nil {
		// 		return nil, 0, err
		// 	}
		// 	return &blob, bytesRead, nil
	}

	return nil, 0, fmt.Errorf("invalid key material magic: 0x%08x", blobMagic.Magic)
}
