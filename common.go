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
