// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

var (
	err error
)

//
// SnmpVersion functions
//

type SnmpVersion int

const (
	Version1       SnmpVersion = 0x0
	Version2c      SnmpVersion = 0x1
	VersionUnknown SnmpVersion = 0xf
)

// implement Stringer interface for SnmpVersion
func (s SnmpVersion) String() string {
	if s == Version1 {
		return "1"
	} else if s == Version2c {
		return "2c"
	}
	return "U"
}

// NewSnmpVersion makes a new SnmpVersion
func NewSnmpVersion(version string) (SnmpVersion, error) {
	if version == "1" {
		return Version1, nil
	} else if version == "2c" {
		return Version2c, nil
	}
	return VersionUnknown, fmt.Errorf("gosnmp: Unknown version %s", version)
}

//
// ObjectIdentifier functions
//

// NewObjectIdentifier makes a new ObjectIdentifier from an Oid string
func NewObjectIdentifier(oid string) (result asn1.ObjectIdentifier, err error) {
	if len(oid) == 0 {
		return nil, fmt.Errorf("gosnmp: invalid oid %s", oid)
	}
	splits := strings.Split(strings.Trim(oid, "."), ".")
	var digits []int
	for _, digit := range splits {
		as_int, err := strconv.Atoi(digit)
		if err != nil {
			return nil, fmt.Errorf("gosnmp: invalid oid %s", oid)
		}
		digits = append(digits, as_int)
	}
	return asn1.ObjectIdentifier(digits), nil
}

// AsString returns the string representation of an Oid
//
// ie the asn1 package *should* implement the Stringer interface,
// but doesn't, so we have to do this manually
func OidAsString(o asn1.ObjectIdentifier) Oid {
	result := fmt.Sprintf("%v", o)
	result = result[1 : len(result)-1] // strip [ ] of Array representation
	return Oid("." + strings.Join(strings.Split(result, " "), "."))
}

// PartitionAll - partition a slice into multiple slices of given
// length, with the last item possibly being of smaller length
//
// See also PartitionAllP for a description, or Clojure's partition-all
// for an example in a different language.
//
func PartitionAll(slice []interface{}, partition_size int) (result [][]interface{}) {
	var accumulator []interface{}
	for counter, item := range slice {
		accumulator = append(accumulator, item)
		if PartitionAllP(counter, partition_size, len(slice)) {
			result = append(result, accumulator)
			accumulator = nil // "truncate" accumulator
		}
	}
	return
}

// PartitionAllP - returns true when dividing a slice into
// partition_size lengths, including last partition which may be smaller
// than partition_size.
//
// For example for a slice of 8 items to be broken into partitions of
// length 3, PartitionAllP returns true for the current_position having
// the following values:
//
// 0  1  2  3  4  5  6  7
//       T        T     T
//
// 'P' stands for Predicate (like foo? in Ruby, foop in Lisp)
//
func PartitionAllP(current_position, partition_size, slice_length int) bool {
	if current_position <= 0 || current_position >= slice_length {
		return false
	}
	if current_position%partition_size == partition_size-1 {
		return true
	}
	if current_position == slice_length-1 {
		return true
	}
	return false
}

// returns true if arg1 and arg2 are within percent % of each other
//
// two zero args are defined as being within any percent of each other, one
// zero arg is defined as never being within any percent of anything else
//
// arg1 and arg2 can be anything numeric - int-like, float-like, uint-like
func WithinPercent(arg1, arg2 interface{}, percent float64) (bool, error) {
	f, err := toFloat64(arg1)
	if err != nil {
		return false, fmt.Errorf("cannot convert arg1: %s", err)
	}
	g, err := toFloat64(arg2)
	if err != nil {
		return false, fmt.Errorf("cannot convert arg2: %s", err)
	}
	switch {
	case f == 0 && g == 0:
		return true, nil
	case f == 0 || g == 0:
		return false, nil
	}
	if f > g {
		f, g = g, f
	}
	return (1 - f/g) <= percent/100, nil
}

// convert i to float64 - helper function for WithinPercent()
func toFloat64(i interface{}) (f float64, err error) {
	switch v := i.(type) {
	case int:
		f = float64(v)
	case int8:
		f = float64(v)
	case int16:
		f = float64(v)
	case int32:
		f = float64(v)
	case int64:
		f = float64(v)
	case uint:
		f = float64(v)
	case uint8:
		f = float64(v)
	case uint16:
		f = float64(v)
	case uint32:
		f = float64(v)
	case uint64:
		f = float64(v)
	case float32:
		f = float64(v)
	case float64:
		f = v
	default:
		return 0, fmt.Errorf("non numeric type %T", v)
	}
	return f, nil
}
