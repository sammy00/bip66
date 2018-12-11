package bip66

func IsValidSignatureEncoding(sig []byte) bool {
	// Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
	// * total-length: 1-byte length descriptor of everything that follows,
	//   excluding the sighash byte.
	// * R-length: 1-byte length descriptor of the R value that follows.
	// * R: arbitrary-length big-endian encoded R value. It must use the shortest
	//   possible encoding for a positive integers (which means no null bytes at
	//   the start, except a single one when the next byte has its highest bit set).
	// * S-length: 1-byte length descriptor of the S value that follows.
	// * S: arbitrary-length big-endian encoded S value. The same rules apply.
	// * sighash: 1-byte value indicating what data is hashed (not part of the DER
	//   signature)

	ell := uint8(len(sig))

	switch {
	case ell < 9 || ell > 73: // Minimum and maximum size constraints.
	case 0x30 != sig[0]: // A signature is of type 0x30 (compound).
	case sig[1] != ell-3: // Make sure the length covers the entire signature.
	default:
		lenR := sig[3] // Extract the length of the R element.

		// Make sure the length of the S element is still inside the signature.
		if 5+lenR >= ell {
			return false
		}

		lenS := sig[5+lenR] // Extract the length of the S element.

		// Verify that the length of the signature matches the sum of the length
		// of the elements.
		if uint8(lenR+lenS+7) != ell {
			return false
		}

		switch {
		case 0x02 != sig[2]: // Check whether the R element is an integer.
		case 0 == lenR: // Zero-length integers are not allowed for R.
		case 0 != 0x80&sig[4]: // Negative numbers are not allowed for R.
		case (lenR > 1) && (0x00 == sig[4]) && (0 == sig[5]&0x80):
		// what about R=0 ??
		// Null bytes at the start of R are not allowed, unless R would
		// otherwise be interpreted as a negative number.
		case 0x02 != sig[lenR+4]: // Check whether the S element is an integer.
		case 0 == lenS: // Zero-length integers are not allowed for S.
		case 0 != 0x80&sig[lenR+6]: // Negative numbers are not allowed for S.
		case (lenS > 1) && (0x00 == sig[lenR+6]) && (0 == 0x80&sig[lenR+7]):
		// what about S=0 ??
		// Null bytes at the start of S are not allowed, unless S would
		// otherwise be interpreted as a negative number.
		default:
			return true
		}
	}

	return false
}
