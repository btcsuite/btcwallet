# btcwallet/btcunit

This package provides a set of idiomatic, type-safe units for handling common
Bitcoin quantities like transaction sizes, weights, and fee rates.

## Purpose

In complex Bitcoin applications, it is crucial to handle different units of
measurement safely and consistently. Raw integer types can lead to ambiguity and
errors (e.g., is a fee rate in sat/byte, sat/vbyte, or sat/kw?).

This package establishes a canonical set of types to be used within `btcwallet`
and by any application that consumes it. By using these types, developers can
avoid conversion errors and make their code more readable and self-documenting.

## Provided Units

- **Transaction Size**: `WeightUnit` and `VByte` for handling transaction
  weight and virtual size according to SegWit (BIP-141) standards.
- **Fee Rates**: `SatPerVByte`, `SatPerKVByte`, and `SatPerKWeight` for
  expressing fee rates in the most common industry formats. These types use
  `math/big.Rat` internally to allow for fractional (sub-satoshi) values,
  ensuring precision in fee calculations. These types use
  `math/big.Rat` internally to allow for fractional (sub-satoshi) values,
  ensuring precision in fee calculations.
