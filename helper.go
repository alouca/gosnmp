// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package go_snmp

import (
	"bytes"
	"errors"
	"fmt"
)

func marshalObjectIdentifier(oid []int) ([]byte, error) {
	out := bytes.NewBuffer(make([]byte, 0, 128))
	if len(oid) < 2 || oid[0] > 6 || oid[1] >= 40 {
		return nil, errors.New("invalid object identifier")
	}
	if err := out.WriteByte(byte(oid[0]*40 + oid[1])); err != nil {
		return nil, err
	}
	for i := 2; i < len(oid); i++ {
		if err := marshalBase128Int(out, int64(oid[i])); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

// parseObjectIdentifier parses an OBJECT IDENTIFIER from the given bytes and
// returns it. An object identifier is a sequence of variable length integers
// that are assigned in a hierarchy.
func parseObjectIdentifier(bytes []byte) ([]int, error) {
	if len(bytes) == 0 {
		return nil, fmt.Errorf("zero length OBJECT IDENTIFIER")
	}

	// In the worst case, we get two elements from the first byte (which is
	// encoded differently) and then every varint is a single byte long.
	s := make([]int, len(bytes)+1)

	// The first byte is 40*value1 + value2:
	s[0] = int(bytes[0]) / 40
	s[1] = int(bytes[0]) % 40
	i := 2
	for offset := 1; offset < len(bytes); i++ {
		v, parseOffset, err := parseBase128Int(bytes, offset)
		if err != nil {
			return nil, err
		}
		offset = parseOffset
		s[i] = v
	}
	s = s[0:i]
	return s, nil
}

// parseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func parseBase128Int(bytes []byte, initOffset int) (int, int, error) {
	var res int
	offset := initOffset
	for shifted := 0; offset < len(bytes); shifted++ {
		if shifted > 4 {
			return 0, 0, fmt.Errorf("structural error: base 128 integer too large")
		}
		res <<= 7
		b := bytes[offset]
		res |= int(b & 0x7f)
		offset++
		if b&0x80 == 0 {
			return res, offset, nil
		}
	}
	return 0, 0, fmt.Errorf("syntax error: truncated base 128 integer")
}

func marshalBase128Int(out *bytes.Buffer, n int64) error {
	if n == 0 {
		return out.WriteByte(0)
	}
	l := 0
	for i := n; i > 0; i >>= 7 {
		l++
	}
	for i := l - 1; i >= 0; i-- {
		o := byte(n >> uint(i*7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}
		if err := out.WriteByte(o); err != nil {
			return err
		}
	}
	return nil
}

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
func parseInt64(bytes []byte) (int64, error) {
	if len(bytes) > 8 {
		// We'll overflow an int64 in this case.
		return 0, errors.New("integer too large")
	}
	var res int64
	for bytesRead := 0; bytesRead < len(bytes); bytesRead++ {
		res <<= 8
		res |= int64(bytes[bytesRead])
	}

	// Shift up and down in order to sign extend the result.
	res <<= 64 - uint8(len(bytes))*8
	res >>= 64 - uint8(len(bytes))*8
	return res, nil
}

func Uvarint(buf []byte) (x uint64) {
	for i, b := range buf {
		x = x<<8 + uint64(b)
		if i == 7 {
			return
		}
	}
	return
}

// BIT STRING

// BitStringValue is the structure to use when you want an ASN.1 BIT STRING type. A
// bit string is padded up to the nearest byte in memory and the number of
// valid bits is recorded. Padding bits will be zero.
type BitStringValue struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

// At returns the bit at the given index. If the index is out of range it
// returns false.
func (b BitStringValue) At(i int) int {
	if i < 0 || i >= b.BitLength {
		return 0
	}
	x := i / 8
	y := 7 - uint(i%8)
	return int(b.Bytes[x]>>y) & 1
}

// RightAlign returns a slice where the padding bits are at the beginning. The
// slice may share memory with the BitString.
func (b BitStringValue) RightAlign() []byte {
	shift := uint(8 - (b.BitLength % 8))
	if shift == 8 || len(b.Bytes) == 0 {
		return b.Bytes
	}
	a := make([]byte, len(b.Bytes))
	a[0] = b.Bytes[0] >> shift
	for i := 1; i < len(b.Bytes); i++ {
		a[i] = b.Bytes[i-1] << (8 - shift)
		a[i] |= b.Bytes[i] >> shift
	}
	return a
}

//// parseBitString parses an ASN.1 bit string from the given byte slice and returns it.
//func parseBitString(bytes []byte) (ret BitStringValue, err error) {
//	if len(bytes) == 0 {
//		err = errors.New("zero length BIT STRING")
//		return
//	}
//	paddingBits := int(bytes[0])
//	if paddingBits > 7 ||
//		len(bytes) == 1 && paddingBits > 0 ||
//		bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
//		err = errors.New("invalid padding bits in BIT STRING")
//		return
//	}
//	ret.BitLength = (len(bytes)-1)*8 - paddingBits
//	ret.Bytes = bytes[1:]
//	return
//}
