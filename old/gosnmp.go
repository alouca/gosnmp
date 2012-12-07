// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
	l "github.com/alouca/gologger"
	"net"
	"time"
)

type GoSNMP struct {
	Target    string
	Community string
	Version   SnmpVersion
	Timeout   time.Duration
	Conn      net.Conn
	Log       *l.Logger
}

func NewGoSNMP(target, community string, version SnmpVersion, timeout int64) (*GoSNMP, error) {
	// Open a UDP connection to the target
	Conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:161", target), time.Duration(timeout)*time.Second)

	if err != nil {
		return nil, fmt.Errorf("Error establishing connection to host: %s\n", err.Error())
	}
	s := &GoSNMP{target, community, version, time.Duration(timeout) * time.Second, Conn, l.CreateLogger(false, false)}

	return s, nil
}

// Enables verbose logging
func (x *GoSNMP) SetVerbose(v bool) {
	x.Log.VerboseFlag = v
}

// Enables debugging
func (x *GoSNMP) SetDebug(d bool) {
	x.Log.DebugFlag = d
}

// Sets the timeout for network read/write functions. Defaults to 5 seconds.
func (x *GoSNMP) SetTimeout(seconds int64) {
	if seconds <= 0 {
		seconds = 5
	}
	x.Timeout = time.Duration(seconds) * time.Second
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

// Debug function
func (x *GoSNMP) Debug(data []byte) (*SnmpPacket, error) {
	packet, err := Unmarshal(data)

	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s\n", err.Error())
	}
	return packet, nil
}

// Get sends an SNMP GET request to the target, for one or more oids.
//
// Get returns a Variable with the response or an error.
func (x *GoSNMP) Get(oids ...string) (pdu *SnmpPacket, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()

	// initialise
	if len(oids) == 0 {
		return nil, errors.New("Get() requires at least one oid")
	}
	x.Conn.SetDeadline(time.Now().Add(x.Timeout))
	packet := SnmpPacket{
		Community:   x.Community,
		Error:       0,
		ErrorIndex:  0,
		RequestType: GetRequest,
		Version:     x.Version,
	}
	//packet.Variables = []SnmpPDU{} ?? allocation required ??
	for _, oid := range oids {
		sp := SnmpPDU{Name: oid, Type: ObjectIdentifier}
		packet.Variables = append(packet.Variables, sp)
	}

	fBuf, err := packet.marshal()
	if err != nil {
		return nil, err
	}

	// send the packet
	_, err = x.Conn.Write(fBuf)
	if err != nil {
		return nil, fmt.Errorf("Error writing to socket: %s\n", err.Error())
	}

	// try to read the response
	resp := make([]byte, 2048, 2048)
	n, err := x.Conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("Error reading from UDP: %s\n", err.Error())
	}

	pdu, err = Unmarshal(resp[:n])
	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s\n", err.Error())
	} else {
		if len(pdu.Variables) < 1 {
			return nil, fmt.Errorf("No responses received.")
		} else {
			return pdu, nil
		}
	}

	return nil, nil
}
