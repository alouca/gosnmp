// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	l "github.com/alouca/gologger"
	"net"
	"strings"
	"time"
)

type GoSNMP struct {
	Target    string
	Community string
	Version   SnmpVersion
	Timeout   time.Duration
	conn      net.Conn
	Log       *l.Logger
}

// Creates a new SNMP Client. Target is the IP address, Community the SNMP Community String and Version the SNMP version.
// Currently only v2c is supported. Timeout parameter is measured in seconds.
func NewGoSNMP(target, community string, version SnmpVersion, timeout int64) (*GoSNMP, error) {
	// Open a UDP connection to the target
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:161", target), time.Duration(timeout)*time.Second)

	if err != nil {
		return nil, fmt.Errorf("Error establishing connection to host: %s\n", err.Error())
	}
	s := &GoSNMP{target, community, version, time.Duration(timeout) * time.Second, conn, l.CreateLogger(false, false)}

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
func (x *GoSNMP) Walk(oid string) (results []SnmpPDU, err error) {
	if oid == "" {
		return nil, fmt.Errorf("No OID given\n")
	}
	results = make([]SnmpPDU, 0)
	requestOid := oid
	for res, err := x.GetNext(oid); err == nil; res, err = x.GetNext(oid) {
		if len(res.Variables) > 0 {
			if strings.Index(res.Variables[0].Name, requestOid) > -1 {
				results = append(results, res.Variables[0])
				// Set to the next
				oid = res.Variables[0].Name
				x.Log.Debug("Moving to %s\n", oid)
			} else {
				x.Log.Debug("Root OID mismatch, stopping walk\n")
				break
			}
		} else {
			break
		}
	}
	return
}

// Marshals & send an SNMP request. Unmarshals the response and returns back the parsed
// SNMP packet
func (x *GoSNMP) sendPacket(packet *SnmpPacket) (*SnmpPacket, error) {
	// Set timeouts on the connection
	deadline := time.Now()
	x.conn.SetDeadline(deadline.Add(x.Timeout))

	// Marshal it
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

	// Unmarshal the read bytes
	pdu, err := Unmarshal(resp[:n])

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

// Sends an SNMP Get Next Request to the target. Returns the next variable response from the OID given or an error
func (x *GoSNMP) GetNext(oid string) (*SnmpPacket, error) {
	var err error
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()

	// Create the packet
	packet := new(SnmpPacket)

	packet.Community = x.Community
	packet.Error = 0
	packet.ErrorIndex = 0
	packet.RequestType = GetNextRequest
	packet.Version = 1 // version 2
	packet.Variables = []SnmpPDU{SnmpPDU{Name: oid, Type: Null}}

	return x.sendPacket(packet)
}

// Debug function. Unmarshals raw bytes and returns the result without the network part
func (x *GoSNMP) Debug(data []byte) (*SnmpPacket, error) {
	packet, err := Unmarshal(data)

	if err != nil {
		return nil, fmt.Errorf("Unable to decode packet: %s\n", err.Error())
	}
	return packet, nil
}

// Sends an SNMP GET request to the target. Returns a Variable with the response or an error
func (x *GoSNMP) Get(oid string) (*SnmpPacket, error) {
	var err error
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()

	// Create the packet
	packet := new(SnmpPacket)

	packet.Community = x.Community
	packet.Error = 0
	packet.ErrorIndex = 0
	packet.RequestType = GetRequest
	packet.Version = 1 // version 2
	packet.Variables = []SnmpPDU{SnmpPDU{Name: oid, Type: Null}}

	return x.sendPacket(packet)
}

// Sends an SNMP GET request to the target. Returns a Variable with the response or an error
func (x *GoSNMP) GetMulti(oids []string) (*SnmpPacket, error) {
	var err error
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()

	// Create the packet
	packet := new(SnmpPacket)

	packet.Community = x.Community
	packet.Error = 0
	packet.ErrorIndex = 0
	packet.RequestType = GetRequest
	packet.Version = 1 // version 2
	packet.Variables = make([]SnmpPDU, len(oids))

	for i, oid := range oids {
		packet.Variables[i] = SnmpPDU{Name: oid, Type: Null}
	}

	return x.sendPacket(packet)
}
