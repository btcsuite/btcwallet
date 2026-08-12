package db

// Nullable represents a value that may be absent without depending on a
// database driver's nullable type.
type Nullable[T any] struct {
	Value T
	Valid bool
}

// NewNullable returns a present nullable value.
func NewNullable[T any](value T) Nullable[T] {
	return Nullable[T]{
		Value: value,
		Valid: true,
	}
}

// Null returns an absent nullable value.
func Null[T any]() Nullable[T] {
	return Nullable[T]{}
}
