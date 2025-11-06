package magic

// Source: bcrypt.h
// Source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
// Source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
// Source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
const (
	// ECDH
	// The key is a 256 bit elliptic curve Diffie-Hellman public key.
	BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345
	// The key is a 256 bit elliptic curve Diffie-Hellman private key.
	BCRYPT_ECDH_PRIVATE_P256_MAGIC = 0x324B4345
	// The key is a 384 bit elliptic curve Diffie-Hellman public key.
	BCRYPT_ECDH_PUBLIC_P384_MAGIC = 0x334B4345
	// The key is a 384 bit elliptic curve Diffie-Hellman private key.
	BCRYPT_ECDH_PRIVATE_P384_MAGIC = 0x344B4345
	// The key is a 521 bit elliptic curve Diffie-Hellman public key.
	BCRYPT_ECDH_PUBLIC_P521_MAGIC = 0x354B4345
	// The key is a 521 bit elliptic curve Diffie-Hellman private key.
	BCRYPT_ECDH_PRIVATE_P521_MAGIC = 0x364B4345

	// ECDSA
	// The key is a 256 bit elliptic curve DSA public key.
	BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345
	// The key is a 256 bit elliptic curve DSA private key.
	BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345
	// The key is a 384 bit elliptic curve DSA public key.
	BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345
	// The key is a 384 bit elliptic curve DSA private key.
	BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345
	// The key is a 521 bit elliptic curve DSA public key.
	BCRYPT_ECDSA_PUBLIC_P521_MAGIC = 0x35534345
	// The key is a 521 bit elliptic curve DSA private key.
	BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 0x36534345

	// DSA
	// Source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
	BCRYPT_DSA_PUBLIC_MAGIC  = 0x42505344
	BCRYPT_DSA_PRIVATE_MAGIC = 0x56505344

	// RSA
	// Source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	BCRYPT_RSAPUBLIC_MAGIC      = 0x31415352
	BCRYPT_RSAPRIVATE_MAGIC     = 0x32415352
	BCRYPT_RSAFULLPRIVATE_MAGIC = 0x33415352

	// Key Data Blob
	// Source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_key_data_blob
	BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4d42444b
)
