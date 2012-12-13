// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
	"reflect"
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

// returns true if arg1 and arg2 are within percent % of each other
//
// two zero args are defined as being equal, one zero arg is defined as
// never being equal to anything else
//
// arg1 and arg2 can be anything numeric - int-like, float-like, uint-like
func WithinPercent(arg1 interface{}, arg2 interface{}, percent float64) (result bool, err error) {

	var float1 float64
	val1 := reflect.ValueOf(arg1)

	switch t1 := arg1.(type) {
	case int, int8, int16, int32, int64:
		float1 = float64(val1.Int())
	case uint, uint8, uint16, uint32, uint64:
		float1 = float64(val1.Uint())
	case float32, float64:
		float1 = val1.Float()
	default:
		return false, fmt.Errorf("arg1 (type %T) isn't numeric", t1)
	}

	var float2 float64
	val2 := reflect.ValueOf(arg2)
	switch t2 := arg2.(type) {
	case int, int8, int16, int32, int64:
		float2 = float64(val2.Int())
	case uint, uint8, uint16, uint32, uint64:
		float2 = float64(val2.Uint())
	case float32, float64:
		float2 = val2.Float()
	default:
		return false, fmt.Errorf("arg2 (type %T) isn't numeric", t2)
	}

	if reflect.DeepEqual(arg1, 0) && reflect.DeepEqual(arg2, 0) {
		return true, nil
	}
	if reflect.DeepEqual(arg1, 0) || reflect.DeepEqual(arg2, 0) {
		return false, nil
	}

	percentf := percent / float64(100)

	if float1 > float2 {
		float1, float2 = float2, float1
	}
	if (1 - (float1 / float2)) < percentf { // 1 - (smaller/larger)
		return true, nil
	}

	return false, nil
}
