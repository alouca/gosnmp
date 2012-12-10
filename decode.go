// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
	"strconv"
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

func (s GoSnmp) DecodeI(ur UnmarshalResults) (dr DecodeResultsI) {
	dr = make(DecodeResultsI)
	for oid, rv := range ur {

		tag := rv.FullBytes[0]
		switch tag {

		// 0x01
		case TagBoolean:
			val := false // a "empty" bool
			if _, err = asn1.Unmarshal(rv.FullBytes, &val); err != nil {
				s.Logger.Printf("BOOLEAN: err: %v", err)
			}
			dr[oid] = val
			s.Logger.Printf("BOOLEAN: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)

		// 0x02, 0x41, 0x42, 0x43
		case TagInteger, TagCounter32, TagGauge32, TagTimeTicks:
			val := int64(0) // an "empty" integer
			// nasty hack: set Tag to Integer, so asn1 doesn't barf with
			// "ASN.1 structure error: tags don't match". Unfortunately,
			// asn1.parseFieldParameters (via UnmarshalWithParams) doesn't
			// allow setting "class:classContextSpecific,tag:1" ie 0x41, nor
			// probably (TODO) would the Unmarshalling handle
			// classContextSpecific
			rv.FullBytes[0] = TagInteger
			if _, err = asn1.Unmarshal(rv.FullBytes, &val); err != nil {
				s.Logger.Printf("INTEGER: err: %v", err)
			}
			s.Logger.Printf("INTEGER: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)
			dr[oid] = val

		// 0x04
		case TagOctetString:
			if len(rv.FullBytes) > 2 && rv.FullBytes[2] == 0x00 {
				// I don't know what these strings that start with 00 are, but
				// doing a hex dump gives the same result as netsnmp
				s.Logger.Printf("STRINGO: 00 string")
				val := fmt.Sprintf("% X", rv.FullBytes[2:]) + " "
				dr[oid] = val
			} else {
				val := []uint8{}
				if _, err = asn1.Unmarshal(rv.FullBytes, &val); err != nil {
					s.Logger.Printf("STRINGO: err: %v", err)
				}
				s.Logger.Printf("STRINGO: fullbytes: % X, tag: %d, decode: %s", rv.FullBytes, tag, val)
				dr[oid] = string(val)
			}

		// 0x06
		case TagOID:
			val, _ := NewObjectIdentifier("0.0") // an "empty" OID
			if _, err = asn1.Unmarshal(rv.FullBytes, &val); err != nil {
				s.Logger.Printf("OID: err: %v", err)
			}
			dr[oid] = OidAsString(val)
			s.Logger.Printf("OID: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)

		// 0x40
		case TagIPAddress:
			var val string
			for _, octet := range rv.Bytes {
				val = val + "." + fmt.Sprintf("%v", octet)
			}
			val = val[1:]
			s.Logger.Printf("IPADDRESS: fullbytes: % X, tag: %d, decode: %s", rv.FullBytes, tag, val)
			dr[oid] = val

		// 0x05, 0x80, 0x81
		case TagNull, TagNoSuchObject, TagNoSuchInstance:
			dr[oid] = ""

		default:
			// TODO cause an exit: want to *notice* unhandled tags
			s.Logger.Fatalf("gonsmp: tag |%x| not decoded", tag)
		}

	}
	return
}

type DecodeResultsS map[Oid]string

// DecodeS decodes UnmarshalResults, and returns all results as strings
//
// This is a convenience function - it just returns the result of %v
// on all values from DecodeI()
func (s GoSnmp) DecodeS(ur UnmarshalResults) (dr_s DecodeResultsS) {
	dr_i := s.DecodeI(ur)
	dr_s = make(DecodeResultsS)
	for key, val := range dr_i {
		dr_s[key] = fmt.Sprintf("%v", val)
	}
	return
}

type DecodeResultsN map[Oid]int64

// DecodeN decodes UnmarshalResults, and returns all results as int64s
//
// This is a convenience function - it just returns the result of %v
// on all values from DecodeI(), converted to int64's
func (s GoSnmp) DecodeN(ur UnmarshalResults) (dr_n DecodeResultsN) {
	dr_i := s.DecodeI(ur)
	dr_n = make(DecodeResultsN)
	for key, val := range dr_i {
		val_s := fmt.Sprintf("%v", val)
		if val_n, err := strconv.ParseInt(val_s, 10, 64); err == nil {
			dr_n[key] = val_n
		} else {
			dr_n[key] = 0
		}
	}
	return
}
