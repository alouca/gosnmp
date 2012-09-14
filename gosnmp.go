// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type GoSNMP struct {
	Target    string
	Community string
	Version   SnmpVersion
	Timeout   time.Duration
	conn      net.Conn
}

// NewGoSNMP opens a UDP connection to the target
func NewGoSNMP(target, community string, version SnmpVersion, timeout int64) (*GoSNMP, error) {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:161", target), time.Duration(timeout)*time.Second)

	if err != nil {
		return nil, fmt.Errorf("Error establishing connection to host: %s\n", err.Error())
	}
	var s *GoSNMP
	//if c, ok := conn.(net.UDPConn); ok {
	s = &GoSNMP{target, community, version, time.Duration(timeout) * time.Second, conn}
	//	}

	return s, nil
}

func marshalOID(oid string) ([]byte, error) {
	var err error

	// Encode the oid
	oid = strings.Trim(oid, ".")
	oidParts := strings.Split(oid, ".")
	oidBytes := make([]int, len(oidParts))

	// Convert the string OID to an array of integers
	for i := 0; i < len(oidParts); i++ {
		oidBytes[i], err = strconv.Atoi(oidParts[i])
		if err != nil {
			return nil, fmt.Errorf("Unable to parse OID: %s\n", err.Error())
		}
	}

	mOid, err := marshalObjectIdentifier(oidBytes)

	if err != nil {
		return nil, fmt.Errorf("Unable to marshal OID: %s\n", err.Error())
	}

	return mOid, err
}

// Sets the timeout for network read/write functions. Defaults to 5 seconds.
func (x *GoSNMP) SetTimeout(seconds int64) {
	if seconds <= 0 {
		seconds = 5
	}
	x.Timeout = time.Duration(seconds) * time.Second
}

func (x *GoSNMP) Close() {
	//x.conn.Close()
}

// StreamWalk will start walking a specified OID, and push through a channel the results
// as it receives them, without waiting for the whole process to finish to return the 
// results
func (x *GoSNMP) StreamWalk(oid string, c chan *Variable) error {

	return nil
}

// Walk will SNMP walk the target, blocking until the process is complete
func (x *GoSNMP) Walk(oid string) ([]*Variable, error) {

	return nil, nil
}

// Sends an SNMP GET request to the target. Returns a Variable with the response or an error
func (x *GoSNMP) Get(oid string) (vbz *Variable, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()

	// Set timeouts on the connection
	deadline := time.Now()
	x.conn.SetDeadline(deadline.Add(x.Timeout * time.Second))

	packet := new(snmpPacket)

	packet.Community = x.Community
	packet.Error = 0
	packet.ErrorIndex = 0
	packet.RequestType = GetRequest
	packet.Version = 1 // version 2
	packet.Variables = []snmpPDU{snmpPDU{Name: oid, Type: Null}}

	fBuf, err := packet.marshal()

	if err != nil {
		return nil, err
	}

	// Send the packet!
	_, err = x.conn.Write(fBuf)
	if err != nil {
		return nil, fmt.Errorf("Error writing to socket: %s\n", err.Error())
	}
	// Try to read the response
	resp := make([]byte, 2048, 2048)
	n, err := x.conn.Read(resp)

	if err != nil {
		return nil, fmt.Errorf("Error reading from UDP: %s\n", err.Error())
	}

	pdu, err := decode(resp[:n])

	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s\n", err.Error())
	} else {
		if len(pdu.VarBindList) < 1 {
			return nil, fmt.Errorf("No responses received.")
		} else {
			return pdu.VarBindList[0], nil
		}
	}

	return nil, nil
}

type MessageType byte

const (
	Sequence   MessageType = 0x30
	GetRequest MessageType = 0xa0
	SetRequest             = 0x1
)

type SnmpVersion uint8

const (
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
)

type snmpPacket struct {
	Version     SnmpVersion
	Community   string
	RequestType MessageType
	RequestID   uint8
	Error       uint8
	ErrorIndex  uint8
	Variables   []snmpPDU
}

type snmpPDU struct {
	Name  string
	Type  Asn1BER
	Value interface{}
}

func (packet *snmpPacket) marshal() ([]byte, error) {
	// Prepare the buffer to send
	buffer := make([]byte, 0, 1024)
	buf := bytes.NewBuffer(buffer)

	// Write the packet header (Message type 0x30) & Version = 2
	buf.Write([]byte{byte(Sequence), 0, 2, 1, byte(packet.Version)})

	// Write Community
	buf.Write([]byte{4, uint8(len(packet.Community))})
	buf.WriteString(packet.Community)

	// Marshal the SNMP PDU
	snmpPduBuffer := make([]byte, 0, 1024)
	snmpPduBuf := bytes.NewBuffer(snmpPduBuffer)

	snmpPduBuf.Write([]byte{byte(packet.RequestType), 0, 2, 1, packet.RequestID, 2, 1, packet.Error, 2, 1, packet.ErrorIndex, byte(Sequence), 0})

	pduLength := 0
	for _, varlist := range packet.Variables {
		pdu, err := marshalPDU(&varlist)

		if err != nil {
			return nil, err
		}
		pduLength += len(pdu)
		snmpPduBuf.Write(pdu)
	}

	pduBytes := snmpPduBuf.Bytes()
	// Varbind list length
	pduBytes[12] = byte(pduLength)
	// SNMP PDU length (PDU header + varbind list length)
	pduBytes[1] = byte(pduLength + 11)

	buf.Write(pduBytes)

	// Write the 
	//buf.Write([]byte{packet.RequestType, uint8(17 + len(mOid)), 2, 1, 1, 2, 1, 0, 2, 1, 0, 0x30, uint8(6 + len(mOid)), 0x30, uint8(4 + len(mOid)), 6, uint8(len(mOid))})
	//buf.Write(mOid)
	//buf.Write([]byte{5, 0})

	ret := buf.Bytes()

	// Set the packet size
	ret[1] = uint8(len(ret) - 2)

	return ret, nil
}

func marshalPDU(pdu *snmpPDU) ([]byte, error) {
	oid, err := marshalOID(pdu.Name)
	if err != nil {
		return nil, err
	}

	pduBuffer := make([]byte, 0, 1024)
	pduBuf := bytes.NewBuffer(pduBuffer)

	// Mashal the PDU type into the appropriate BER
	switch pdu.Type {
	case Null:
		pduBuf.Write([]byte{byte(Sequence), byte(len(oid) + 4)})
		pduBuf.Write([]byte{byte(ObjectIdentifier), byte(len(oid))})
		pduBuf.Write(oid)
		pduBuf.Write([]byte{Null, 0x00})
	default:
		return nil, fmt.Errorf("Unable to marshal PDU: uknown BER type %d", pdu.Type)
	}

	return pduBuf.Bytes(), nil
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 noexpandtab
// run 'go fmt' before checking in your code!
