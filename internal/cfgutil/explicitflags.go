// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cfgutil

// ExplicitString is a string value implementing the flags.Marshaler and
// flags.Unmarshaler interfaces so it may be used as a config struct field.  It
// records whether the value was explicitly set by the flags package.  This is
// useful when behavior must be modified depending on whether a flag was set by
// the user or left as a default.  Without recording this, it would be
// impossible to determine whether flag with a default value was unmodified or
// explicitly set to the default.
type ExplicitString struct {
	Value         string
	explicitlySet bool
}

// NewExplicitString creates a string flag with the provided default value.
func NewExplicitString(defaultValue string) *ExplicitString {
	return &ExplicitString{Value: defaultValue, explicitlySet: false}
}

// ExplicitlySet returns whether the flag was explicitly set through the
// flags.Unmarshaler interface.
func (e *ExplicitString) ExplicitlySet() bool { return e.explicitlySet }

// MarshalFlag implements the flags.Marshaler interface.
func (e *ExplicitString) MarshalFlag() (string, error) { return e.Value, nil }

// UnmarshalFlag implements the flags.Unmarshaler interface.
func (e *ExplicitString) UnmarshalFlag(value string) error {
	e.Value = value
	e.explicitlySet = true
	return nil
}
