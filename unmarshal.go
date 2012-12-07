// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
)

type UMSG struct {
	//
	// the Raw asn1.RawContent field allows us to see the raw
	// bytes contained with the associated struct - handy for debugging
	//
	Raw       asn1.RawContent
	Version   int
	Community []byte
	Pdu       UPDU `asn1:"implicit,tag:2"` // SNMP RESPONSE is second context specific tag
}

type UPDU struct {
	//
	// the Raw asn1.RawContent field allows us to see the raw
	// bytes contained with the associated struct - handy for debugging
	//
	Raw        asn1.RawContent
	RequestID  int
	Error      int
	ErrorIndex int
	Varbinds   []UVarbind
}

type UVarbind struct {
	//
	// the Raw asn1.RawContent field allows us to see the raw
	// bytes contained with the associated struct - handy for debugging
	//
	Raw asn1.RawContent
	Oid asn1.ObjectIdentifier
	//
	// Value has type asn1.RawValue, as we don't know what tag will be
	// returned.
	//
	// asn1.RawValue is defined as:
	//
	// type RawValue struct {
	//     Class, Tag int
	//     IsCompound bool
	//     Bytes      []byte
	//     FullBytes  []byte // includes the tag and length
	// }
	//
	// Therefore rv.Class should give 0 (ie built-in), rv.Tag gives type
	// (eg tagInteger 2, tagOctetString 4, tagOID 6, etc), and rv.Bytes
	// gives value, which can be converted into appropriate representation.
	//
	Value asn1.RawValue
}

type Oid string

type UnmarshalResults map[Oid]asn1.RawValue

func Unmarshal(msg []byte) (ur UnmarshalResults, err error) {
	ur = make(UnmarshalResults)
	var m UMSG
	rest, err := asn1.Unmarshal(msg, &m)
	if len(rest) != 0 {
		return nil, fmt.Errorf("gosnmp: incomplete parse: %x", rest)
	}
	if err != nil {
		return nil, fmt.Errorf("gosnmp: %s", err.Error())
	}

	// TODO check the error field results. Page 6 of Infrax doc
	// err index - varbind that caused error
	/*
		const (
			errNoError = 0
			errTooBig = 1
			errNoSuchName = 2
			errBadValue = 3
			errReadOnly = 4
			errGenErr = 5
			... thru to 18
		)
	*/

	for _, v := range m.Pdu.Varbinds {
		ur[OidAsString(v.Oid)] = v.Value
	}
	return ur, nil
}
