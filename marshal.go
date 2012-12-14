// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
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
	Pdu       PDU    `asn1:"implicit,tag:0"` // SNMP GET is zero'th context specific class
}

func (s GoSnmp) Marshal(oids []string) (marshalled_msg []byte, err error) {
	var varbinds []Varbind
	for _, o := range oids {
		var oid asn1.ObjectIdentifier
		if oid, err = NewObjectIdentifier(o); err != nil {
			return nil, fmt.Errorf("gosnmp: %s", err.Error())
		}
		varbind := Varbind{Oid: oid, Value: asn1.RawValue{Tag: 5}} // 5 - tag = Null
		varbinds = append(varbinds, varbind)
	}

	pdu := PDU{RequestID: 1, Error: 0, ErrorIndex: 0, Varbinds: varbinds}
	msg := Msg{Version: int(s.Version), Community: []byte(s.Community), Pdu: pdu}

	if marshalled_msg, err = asn1.Marshal(msg); err != nil {
		return nil, fmt.Errorf("gosnmp: %s", err.Error())
	}
	return
}
