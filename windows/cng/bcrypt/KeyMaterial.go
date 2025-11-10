package bcrypt

// KeyMaterial is an interface that represents a key material in memory.
//
// It provides methods for unmarshalling, marshalling, and comparing key materials.
type KeyMaterial interface {
	Unmarshal(data []byte) (int, error)
	Marshal() ([]byte, error)
	String() string
	Equal(other KeyMaterial) bool
	Describe(indent int)
}
