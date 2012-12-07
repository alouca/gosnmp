// Copyright 2012 Sonia Hamilton <sonia@snowfroasn1net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// The article by Rane [1] gives an excellent overview of the SNMP
// Marshalling process ie converting an snmp command in to an array of
// bytes suitable for writing to a network connection.
//
// [1] http://www.rane.com/note161.html
//
// This program is an example of how to unmarshal a message that contains
// the following oids and values:
//
// oid: .1.3.6.1.2.1.1.7.0 # 104
// oid: .1.3.6.1.2.1.2.1.0 # 2
//
// The received data looks like this:
//
// 30 36 02 01 01 04 06 70 75 62 6C 69 63 A2 29 02 01 01 02 01 00
// 02 01 00 30 1E 30 0D 06 08 2B 06 01 02 01 02 01 00 02 01 02 30
// 0D 06 08 2B 06 01 02 01 01 07 00 02 01 68
//
// ie manually unpacked it is:
//
// 30 36                                               # msg
// 02 01 01                                            # version
// 04 06 70 75 62 6C 69 63                             # community
// A2 29                                               # snmp response
// 02 01 01                                            # request
// 02 01 00                                            # error
// 02 01 00                                            # error idx
// 30 1E                                               # varbind list
// 30 0D 06 08 2B 06 01 02 01 02 01 00                 # oid
// 02 01 02                                            # value (2)
// 30 0D 06 08 2B 06 01 02 01 01 07 00                 # oid
// 02 01 68                                            # value (104)
//
// Hopefully this program will help other developers understand the
// unmarshalling process used in the gosnmp library. Run it using the
// command:
//
// % go run unmarshal.go

package main

import (
	"encoding/asn1"
	"fmt"
	"log"
	"runtime/debug"
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

var hex = []byte{0x30, 0x36, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA2, 0x29, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x1E, 0x30, 0x0D, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x02, 0x30, 0x0D, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00, 0x02, 0x01, 0x68}

func main() {
	var m UMSG
	_, err := asn1.Unmarshal(hex, &m)
	die(err)
	fmt.Printf("raw:% X\nversion:%d community:%s\n\n", m.Raw, m.Version, m.Community)
	fmt.Printf("raw:% X\nrequestid:%d error:%d errorindex:%d\n\n",
		m.Pdu.Raw, m.Pdu.RequestID, m.Pdu.Error, m.Pdu.ErrorIndex)

	fmt.Printf("varbind[0] raw:% X\noid:%v\nvalue:%v\n\n",
		m.Pdu.Varbinds[0].Raw, m.Pdu.Varbinds[0].Oid, m.Pdu.Varbinds[0].Value)
	fmt.Printf("varbind[1] raw:% X\noid:%v\nvalue:%v\n\n",
		m.Pdu.Varbinds[1].Raw, m.Pdu.Varbinds[1].Oid, m.Pdu.Varbinds[1].Value)
}

// die is a generic log and exit error handler
func die(err error) {
	if err != nil {
		debug.PrintStack()
		log.Fatal(err)
	}
}
