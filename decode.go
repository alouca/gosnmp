// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
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

//
// Types for each Tag
//

// TagBoolean
type TagResultBoolean bool

func (r TagResultBoolean) Integer() int64 {
	if r {
		return 1
	}
	return 0
}

func (r TagResultBoolean) String() string {
	if r {
		return "true"
	}
	return "false"
}

// TagOctetString
type TagResultOctetString string

func (r TagResultOctetString) Integer() int64 {
	return 0
}

func (r TagResultOctetString) String() string {
	return fmt.Sprintf("%s", string(r))
}

// TagOID
type TagResultOID struct{}

func (r TagResultOID) String() string {
	return "TODO - OID"
}

func (r TagResultOID) Integer() int64 {
	return -1
}

// TagIPAddress
// TODO ip address really should be stored as an int,
// then String() should convert to dotted form
type TagResultIPAddress string

func (r TagResultIPAddress) Integer() int64 {
	return -1
}

func (r TagResultIPAddress) String() string {
	return fmt.Sprintf("%s", string(r))
}

//
// the "Integers"
//

// TagInteger
type TagResultInteger int64

func (r TagResultInteger) Integer() int64 {
	return int64(r)
}

func (r TagResultInteger) String() string {
	return fmt.Sprintf("%d", r)
}

// TagCounter32
type TagResultCounter32 int64

func (r TagResultCounter32) Integer() int64 {
	return int64(r)
}

func (r TagResultCounter32) String() string {
	return fmt.Sprintf("%d", r)
}

// TagGauge32
type TagResultGauge32 int64

func (r TagResultGauge32) Integer() int64 {
	return int64(r)
}

func (r TagResultGauge32) String() string {
	return fmt.Sprintf("%d", r)
}

// TagTimeTicks
type TagResultTimeTicks int64

func (r TagResultTimeTicks) Integer() int64 {
	return int64(r)
}

func (r TagResultTimeTicks) String() string {
	return fmt.Sprintf("%d", r)
}

// TagCounter64
type TagResultCounter64 int64

func (r TagResultCounter64) Integer() int64 {
	return int64(r)
}

func (r TagResultCounter64) String() string {
	return fmt.Sprintf("%d", r)
}

//
// The "Fails"
//

// TagNull
type TagResultNull struct{}

func (r TagResultNull) Integer() int64 {
	return 0
}

func (r TagResultNull) String() string {
	return "NULL"
}

// TagNoSuchObject
type TagResultNoSuchObject struct{}

func (r TagResultNoSuchObject) Integer() int64 {
	return 0
}

func (r TagResultNoSuchObject) String() string {
	return "NO SUCH OBJECT"
}

// TagNoSuchInstance
type TagResultNoSuchInstance struct{}

func (r TagResultNoSuchInstance) Integer() int64 {
	return 0
}

func (r TagResultNoSuchInstance) String() string {
	return "NO SUCH INSTANCE"
}

//
// FullDecode
//

type FullResult struct {
	Value Taggish
	Debug string // debugging messages
	Error error  // decoding errors, not "No Such Object", "Null", etc
}

type Taggish interface {
	Integer() int64
	fmt.Stringer
}

type FullDecodeResults map[Oid]*FullResult

func (s GoSnmp) FullDecode(ur UnmarshalResults) (r FullDecodeResults) {
	r = make(FullDecodeResults)

	for oid, rv := range ur {
		tag := rv.FullBytes[0]
		switch tag {

		// 0x01
		case TagBoolean:
			var (
				debug string
				merr  error
				val   bool
			)

			if _, merr = asn1.Unmarshal(rv.FullBytes, &val); err != nil {
				debug = fmt.Sprintf("BOOLEAN: err: %v", err)
			} else {
				debug = fmt.Sprintf("BOOLEAN: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)
			}

			r[oid] = &FullResult{
				Value: TagResultBoolean(val),
				Debug: debug,
				Error: merr,
			}

		// 0x02, 0x41, 0x42, 0x43, 0x46
		case TagInteger, TagCounter32, TagGauge32, TagTimeTicks, TagCounter64:
			var (
				debug string
				merr  error
				val   int
			)

			// nasty hack: set Tag to Integer, so asn1 doesn't barf with
			// "ASN.1 structure error: tags don't match". Unfortunately,
			// asn1.parseFieldParameters (via UnmarshalWithParams) doesn't
			// allow setting "class:classContextSpecific,tag:1" ie 0x41, nor
			// probably (TODO) would the Unmarshalling handle
			// classContextSpecific
			rv.FullBytes[0] = TagInteger

			if _, merr = asn1.Unmarshal(rv.FullBytes, &val); err != nil {
				debug = fmt.Sprintf("INTEGER: err: %v", err)
			} else {
				debug = fmt.Sprintf("INTEGER: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)
			}

			fr := &FullResult{
				Debug: debug,
				Error: merr,
			}
			switch tag {
			case TagInteger:
				fr.Value = TagResultInteger(val)
			case TagCounter32:
				fr.Value = TagResultCounter32(val)
			case TagGauge32:
				fr.Value = TagResultGauge32(val)
			case TagTimeTicks:
				fr.Value = TagResultTimeTicks(val)
			case TagCounter64:
				fr.Value = TagResultCounter64(val)
			}
			r[oid] = fr

		// 0x04
		case TagOctetString:
			var (
				debug string
				merr  error
				val   string
			)

			if len(rv.FullBytes) > 2 && rv.FullBytes[2] == 0x00 {
				// I don't know what these strings that start with 00 are, but
				// doing a hex dump gives the same result as netsnmp
				debug = "OCTETSTRING: 00 string"
				val = fmt.Sprintf("% X", rv.FullBytes[2:]) + " "
			} else {
				ui := []uint8{}
				if _, merr = asn1.Unmarshal(rv.FullBytes, &ui); err != nil {
					debug = fmt.Sprintf("OCTETSTRING: err: %v", err)
				} else {
					val = string(ui)
					debug = fmt.Sprintf("OCTETSTRING: fullbytes: % X, tag: %d, decode: %s", rv.FullBytes, tag, val)
				}
			}

			r[oid] = &FullResult{
				Value: TagResultOctetString(val),
				Debug: debug,
				Error: merr,
			}

		// 0x06
		case TagOID:
			// TODO skip oids for the moment
			r[oid] = &FullResult{
				Value: new(TagResultOID),
			}
			/*
				val, _ := NewObjectIdentifier("0.0") // an "empty" OID
				if _, err = asn1.Unmarshal(rv.FullBytes, &val); err != nil {
					s.Logger.Printf("OID: err: %v", err)
				}
				r[oid] = OidAsString(val)
				s.Logger.Printf("OID: fullbytes: % X, tag: %d, decode: %v", rv.FullBytes, tag, val)
			*/

		// 0x40
		case TagIPAddress:
			var (
				debug string
				val   string
			)

			for _, octet := range rv.Bytes {
				val = val + "." + fmt.Sprintf("%v", octet)
			}
			val = val[1:]
			debug = fmt.Sprintf("IPADDRESS: fullbytes: % X, tag: %d, decode: %s", rv.FullBytes, tag, val)

			r[oid] = &FullResult{
				Value: TagResultIPAddress(val),
				Debug: debug,
			}

		//
		// The "Fails"
		//

		// 0x05
		case TagNull:
			r[oid] = &FullResult{
				Value: new(TagResultNull),
				Debug: fmt.Sprintf("NULL: fullbytes: % X, tag: %d", rv.FullBytes, tag),
			}

		// 0x80
		case TagNoSuchObject:
			r[oid] = &FullResult{
				Value: new(TagResultNoSuchObject),
				Debug: fmt.Sprintf("NOSUCHOBJECT: fullbytes: % X, tag: %d", rv.FullBytes, tag),
			}

		// 0x81
		case TagNoSuchInstance:
			r[oid] = &FullResult{
				Value: new(TagResultNoSuchInstance),
				Debug: fmt.Sprintf("NOSUCHINSTANCE: fullbytes: % X, tag: %d", rv.FullBytes, tag),
			}

		default:
			// TODO cause an exit: want to *notice* unhandled tags
			s.Logger.Fatalf("gonsmp: tag |%x| unhandled", tag)

		}
	}
	return
}
