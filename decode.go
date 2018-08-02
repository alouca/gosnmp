// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package go_snmp

import (
	"fmt"
	"errors"
	"net"
)

type Asn1BER byte

// SNMP Data Types
const (
	Integer          Asn1BER = 0x02
	BitString                = 0x03
	OctetString              = 0x04
	Null                     = 0x05
	ObjectIdentifier         = 0x06
	Sequence                 = 0x30
	IpAddress                = 0x40
	Counter32                = 0x41
	Gauge32                  = 0x42
	TimeTicks                = 0x43
	Opaque                   = 0x44
	NsapAddress              = 0x45
	Counter64                = 0x46
	Uinteger32               = 0x47
	NoSuchObject             = 0x80
	NoSuchInstance           = 0x81
	GetRequest               = 0xa0
	GetNextRequest           = 0xa1
	GetResponse              = 0xa2
	SetRequest               = 0xa3
	Trap                     = 0xa4
	GetBulkRequest           = 0xa5
	EndOfMibView             = 0x82
)

// String representations of each SNMP Data Type
var dataTypeStrings = map[Asn1BER]string{
	Integer:          "Integer",
	BitString:        "BitString",
	OctetString:      "OctetString",
	Null:             "Null",
	ObjectIdentifier: "ObjectIdentifier",
	IpAddress:        "IpAddress",
	Sequence:         "Sequence",
	Counter32:        "Counter32",
	Gauge32:          "Gauge32",
	TimeTicks:        "TimeTicks",
	Opaque:           "Opaque",
	NsapAddress:      "NsapAddress",
	Counter64:        "Counter64",
	Uinteger32:       "Uinteger32",
	NoSuchObject:     "NoSuchObject",
	NoSuchInstance:   "NoSuchInstance",
	GetRequest:       "GetRequest",
	GetNextRequest:   "GetNextRequest",
	GetResponse:      "GetResponse",
	SetRequest:       "SetRequest",
	Trap:             "Trap",
	GetBulkRequest:   "GetBulkRequest",
	EndOfMibView:     "endOfMib",
}

func (dataType Asn1BER) String() string {
	str, ok := dataTypeStrings[dataType]
	if !ok {
		str = "Unknown"
	}
	return str
}

type Variable struct {
	Name  []int
	Type  Asn1BER
	Size  uint64
	Value interface{}
}

func decodeValue(valueType Asn1BER, data []byte) (*Variable, error) {
	v := &Variable{Size: uint64(len(data))}
	switch valueType {
	case Integer:
		ret, err := parseInt(data)
		if err != nil {
			break
		}
		v.Type = Integer
		v.Value = ret
	case OctetString:
		v.Type = OctetString
		v.Value = string(data)
	case ObjectIdentifier:
		v.Type = ObjectIdentifier
		v.Value, _ = parseObjectIdentifier(data)
	case IpAddress:
		v.Type = IpAddress
		v.Value = net.IP(data)
	case Counter32:
		v.Type = Counter32
		v.Value = Uvarint(data)
	case TimeTicks:
		ret, err := parseInt(data)
		if err != nil {
			break
		}
		v.Type = TimeTicks
		v.Value = ret
	case Gauge32:
		v.Type = Gauge32
		v.Value = Uvarint(data)
	case Counter64:
		v.Type = Counter64
		v.Value = Uvarint(data)
	case Null:
		v.Value = nil
	case Sequence:
		// NOOP
		v.Value = data
	case GetResponse:
		// NOOP
		v.Value = data
	case GetRequest:
		// NOOP
		v.Value = data
	case EndOfMibView:
		v.Type = EndOfMibView
		v.Value = "endOfMib"
	case GetBulkRequest:
		// NOOP
		v.Value = data
	case NoSuchInstance:
		return nil, fmt.Errorf("no such instance")
	case NoSuchObject:
		return nil, fmt.Errorf("no such object")
	default:
		return nil, fmt.Errorf("unable to decode %s %#v - not implemented", valueType, valueType)
	}
	return v, nil
}

// parseInt treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseInt(bytes []byte) (int, error) {
	res, err := parseInt64(bytes)
	if err != nil {
		return 0, err
	}
	if res != int64(int(res)) {
		return 0, errors.New("integer too large")
	}
	return int(res), nil
}
