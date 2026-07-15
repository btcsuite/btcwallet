package sqlstore

import "fmt"

const (
	maxUint8  = int64(^uint8(0))
	maxUint32 = int64(^uint32(0))
	minInt32  = int64(-1 << 31)
	maxInt32  = int64(1<<31 - 1)
)

// CheckedUint8 converts a SQL integer into a durable uint8 field.
func CheckedUint8(value int64, field string) (uint8, error) {
	if value < 0 || value > maxUint8 {
		return 0, fmt.Errorf("%s value %d overflows uint8", field, value)
	}

	return uint8(value), nil
}

// CheckedUint32 converts a SQL integer into a durable uint32 field.
func CheckedUint32(value int64, field string) (uint32, error) {
	if value < 0 || value > maxUint32 {
		return 0, fmt.Errorf("%s value %d overflows uint32", field, value)
	}

	return uint32(value), nil
}

// CheckedInt32 converts a SQL integer into a durable int32 field.
func CheckedInt32(value int64, field string) (int32, error) {
	if value < minInt32 || value > maxInt32 {
		return 0, fmt.Errorf("%s value %d overflows int32", field, value)
	}

	return int32(value), nil
}
