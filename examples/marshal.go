// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.
//
// The article by Rane [1] gives an excellent overview of the SNMP
// Marshalling process ie converting an snmp command in to an array of
// bytes suitable for writing to a network connection.
//
// [1] http://www.rane.com/note161.html
//
// This program is an example of how to marshall the message given in
// figure 3 page 5 of that article, that is marshalling a GoSNMP message
// similar to this NetSNMP command:
//
// % snmpget -Oq -On -c private -v 1 192.168.1.10 .1.3.6.1.4.1.2680.1.2.7.3.2.0
//
// into this byte array:
//
// 30 2C                          # Message
// 02 01 00                       # Version
// 04 07 70 72 69 76 61 74 65     # Community "private"
// A0 1E                          # PDU
// 02 01 01                       # Request ID
// 02 01 00                       # Error
// 02 01 00                       # Error Index
// 30 13                          # Varbind List
// 30 11                          # Varbind
// 06 0D 2B 06 01 04 01 94 78 01 02 07 03 02 00   # OID
// 05 00                          # Value (null)
//
// Hopefully this program will help other developers understand the
// marshalling process used in the gosnmp library. Run it using the
// command:
//
// % go run marshal.go
//
// It could be extended by adding multiple varbinds, then comparing the
// result to a packet capture in Wireshark:
//
//  vb1 := Varbind{
//    Oid:   asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 2680, 1, 2, 7, 3, 1, 0}),
//    Value: asn1.RawValue{Tag: 5}, // 5 - tag = Null
//  }
//  vb3 := Varbind{
//    Oid:   asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 2680, 1, 2, 7, 3, 3, 0}),
//    Value: asn1.RawValue{Tag: 5}, // 5 - tag = Null
//  }
//  pdu := PDU{
//    ....
//    Varbinds:   []Varbind{vb1, vb2, vb3},
//  }

package main

import (
	"encoding/asn1"
	"log"
	"runtime/debug"
)

type Varbind struct {
	Oid   asn1.ObjectIdentifier
	Value asn1.RawValue
}

type PDU struct {
	RequestID  int
	Error      int
	ErrorIndex int
	Varbinds   []Varbind
}

type Msg struct {
	Version   int
	Community []byte // Octet means byte, ie OctetString means []byte
	Pdu       PDU    `asn1:"implicit,tag:0"` // SNMP GET is zero'th context specific tag
}

var (
	err error
)

func main() {
	vb2 := Varbind{
		Oid:   asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 2680, 1, 2, 7, 3, 2, 0}),
		Value: asn1.RawValue{Tag: 5}, // 5 - tag = Null
	}
	pdu := PDU{
		RequestID:  1,
		Error:      0,
		ErrorIndex: 0,
		Varbinds:   []Varbind{vb2},
	}
	m := Msg{
		Version:   0, // snmp v1
		Community: []byte("private"),
		Pdu:       pdu,
	}
	mm, err := asn1.Marshal(m)
	die(err)
	log.Printf("Msg: % X\n", mm)
}

// die is a generic log and exit error handler
func die(err error) {
	if err != nil {
		debug.PrintStack()
		log.Fatal(err)
	}
}
