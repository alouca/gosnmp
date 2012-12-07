// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"log"
)

const (
	// `grep define include/net-snmp/library/*.h | grep 0x0123456789`
	// especially asn1.h
	TagBoolean         = 0x01 // Class 0 (Universal), Tag 1
	TagInteger         = 0x02 // Class 0 (Universal), Tag 2
	TagBitString       = 0x03 // Class 0 (Universal), Tag 3
	TagOctetString     = 0x04 // Class 0 (Universal), Tag 4
	TagNull            = 0x05 // Class 0 (Universal), Tag 5
	TagOID             = 0x06 // Class 0 (Universal), Tag 6
	TagEnum            = 0x0A // Class 0 (Universal), Tag 10
	TagUTF8String      = 0x0C // Class 0 (Universal), Tag 12
	TagSequence        = 0x10 // Class 0 (Universal), Tag 16
	TagSet             = 0x11 // Class 0 (Universal), Tag 17
	TagPrintableString = 0x13 // Class 0 (Universal), Tag 19
	TagT61String       = 0x14 // Class 0 (Universal), Tag 20
	TagIA5String       = 0x16 // Class 0 (Universal), Tag 22
	TagUTCTime         = 0x17 // Class 0 (Universal), Tag 23
	TagGeneralizedTime = 0x18 // Class 0 (Universal), Tag 24
	TagGeneralString   = 0x1B // Class 0 (Universal), Tag 27
	TagIPAddress       = 0x40 // Class 1 (Application), Tag 0
	TagCounter32       = 0x41 // Class 1 (Application), Tag 1
	TagGauge32         = 0x42 // Class 1 (Application), Tag 2
	TagTimeTicks       = 0x43 // Class 1 (Application), Tag 3
	TagOpaque          = 0x44 // Class 1 (Application), Tag 4
	TagNsapAddress     = 0x45 // Class 1 (Application), Tag 5
	TagCounter64       = 0x46 // Class 1 (Application), Tag 6
	TagUinteger32      = 0x47 // Class 1 (Application), Tag 7
	TagNoSuchObject    = 0x80 // Class 2 (Context Specific), Tag 0
	TagNoSuchInstance  = 0x81 // Class 2 (Context Specific), Tag 1
)

type DecodeResultsI map[Oid]interface{}

func DecodeI(ur UnmarshalResults) (dr DecodeResultsI) {
	dr = make(DecodeResultsI)
	for oid, rv := range ur {

		tag := rv.FullBytes[0]
		switch tag {

		// 0x01
		case TagBoolean:
			val := false // a "empty" bool
			if _, err = asn1.Unmarshal(rv.FullBytes, &val); err == nil {
				dr[oid] = val
			}
			log.Printf("BOOLEAN: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)

		// 0x02 , 0x41 , 0x42 , 0x43
		case TagInteger, TagCounter32, TagGauge32, TagTimeTicks:
			val := int64(0) // an "empty" integer
			if _, err = asn1.Unmarshal(rv.FullBytes, &val); err == nil {
				dr[oid] = val
			}
			log.Printf("INTEGER: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)

		// 0x04
		case TagOctetString:
			val := string(rv.Bytes)
			log.Printf("STRING: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)
			dr[oid] = val

		// 0x06
		case TagOID:
			val, _ := NewObjectIdentifier("0.0") // an "empty" OID
			if _, err = asn1.Unmarshal(rv.FullBytes, &val); err == nil {
				dr[oid] = OidAsString(val)
			}
			log.Printf("OID: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)

		// 0x40
		case TagIPAddress:
			// TODO copy asn1/* into gosnmp/asn1/*, or just manually decode this field?
			dr[oid] = "gosnmp: TODO: unmarshal 0x40 ipaddress"

		// 0x05, 0x80, 0x81
		case TagNull, TagNoSuchObject, TagNoSuchInstance:
			dr[oid] = nil

		default:
			// TODO cause an exit: want to *notice* unhandled tags
			log.Fatalf("gonsmp: tag |%x| not decoded", tag)
		}

	}
	return
}

// TODO
type DecodeResultsS map[Oid]string

func DecodeS(ur UnmarshalResults) (dr DecodeResultsS) {
	// just do %v on all fields??
	return
}

// TODO
type DecodeResultsN map[Oid]int64

func DecodeN(ur UnmarshalResults) (dr DecodeResultsN) {
	// return 0 for string, etc fields
	return
}
