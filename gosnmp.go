// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Client represents the SNMP client
type Client struct {
	Host      string
	Community string
	Version   SnmpVersion
	Timeout   time.Duration
	conn      net.Conn
}

// NewClient creates a new SNMP client. Host is the IP address, Community
// the SNMP Community String and Version the SNMP version. Currently only v2c
// is supported. Timeout parameter is measured in seconds.
func NewClient(host, community string, version SnmpVersion, timeout int64) (*Client, error) {
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "161")
	}
	conn, err := net.DialTimeout("udp", host, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("error establishing connection to host: %s\n", err.Error())
	}
	s := &Client{
		Host:      host,
		Community: community,
		Version:   version,
		Timeout:   time.Duration(timeout) * time.Second,
		conn:      conn,
	}
	return s, nil
}

// Close closes the UDP client connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// SetTimeout sets the timeout for network read/write functions. Defaults to 5 seconds.
func (c *Client) SetTimeout(seconds int64) {
	if seconds <= 0 {
		seconds = 5
	}
	c.Timeout = time.Duration(seconds) * time.Second
}

// StreamWalk will start walking a specified OID, and push through a channel the results
// as it receives them, without waiting for the whole process to finish to return the
// results. Once it has completed the walk, the channel is closed.
func (c *Client) StreamWalk(oid string, pdus chan SnmpPDU) error {
	defer close(pdus)

	if oid == "" {
		return fmt.Errorf("no OID given")
	}
	for {
		res, err := c.GetNext(oid)
		if err != nil {
			return err
		}
		if res == nil {
			break
		}
		if len(res.Variables) <= 0 {
			break
		}
		if strings.Index(res.Variables[0].Name, oid) <= -1 {
			break
		}
		if res.Variables[0].Value == "endOfMib" {
			break
		}
		pdus <- res.Variables[0]
		// Set to the next
		oid = res.Variables[0].Name
	}
	return nil
}

// BulkWalk sends an walks the target using SNMP BULK-GET requests. This returns
// a Variable with the response and the error condition
func (c *Client) BulkWalk(maxRepetitions uint8, oid string) ([]SnmpPDU, error) {
	if oid == "" {
		return nil, fmt.Errorf("no OID given")
	}
	return c.bulkWalk(maxRepetitions, oid, oid)
}

func (c *Client) bulkWalk(maxRepetitions uint8, searchingOid string, rootOid string) ([]SnmpPDU, error) {
	response, err := c.GetBulk(0, maxRepetitions, searchingOid)
	if err != nil {
		return nil, err
	}
	var results []SnmpPDU
	for i, v := range response.Variables {
		if v.Value == "endOfMib" {
			return nil, nil
		}
		// is this variable still in the requested oid range
		if strings.HasPrefix(v.Name, rootOid) {
			results = append(results, v)
			// is the last oid received still in the requested range
			if i == len(response.Variables)-1 {
				var subResults []SnmpPDU
				subResults, err = c.bulkWalk(maxRepetitions, v.Name, rootOid)
				if err != nil {
					return nil, err
				}
				results = append(results, subResults...)
			}
		}
	}
	return results, nil
}

// Walk will SNMP walk the target, blocking until the process is complete
func (c *Client) Walk(oid string) ([]SnmpPDU, error) {
	if oid == "" {
		return nil, fmt.Errorf("No OID given\n")
	}
	results := make([]SnmpPDU, 0)
	requestOid := oid
	for {
		res, err := c.GetNext(oid)
		if err != nil {
			return results, err
		}
		if res == nil {
			break
		}
		if len(res.Variables) <= 0 {
			break
		}
		if strings.Index(res.Variables[0].Name, requestOid) <= -1 {
			break
		}
		results = append(results, res.Variables[0])
		// Set to the next
		oid = res.Variables[0].Name
	}
	return results, nil
}

// sendPacket marshals & send an SNMP request. Unmarshals the response and
// returns back the parsed SNMP packet
func (c *Client) sendPacket(packet *SnmpPacket) (*SnmpPacket, error) {
	// Set timeouts on the connection
	deadline := time.Now()
	c.conn.SetDeadline(deadline.Add(c.Timeout))

	// Create random Request-ID
	packet.RequestID = rand.Uint32()

	// Marshal it
	fBuf, err := packet.marshal()

	if err != nil {
		return nil, err
	}

	// Send the packet!
	_, err = c.conn.Write(fBuf)
	if err != nil {
		return nil, fmt.Errorf("error writing to socket: %v", err)
	}
	// Try to read the response
	resp := make([]byte, 8192, 8192)
	n, err := c.conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("error reading from UDP: %v", err)
	}

	// Unmarshal the read bytes
	pdu, err := Unmarshal(resp[:n])

	if err != nil {
		return nil, fmt.Errorf("unable to decode packet: %v", err)
	}

	if len(pdu.Variables) < 1 {
		return nil, fmt.Errorf("no responses received")
	}

	// check Request-ID
	if pdu.RequestID != packet.RequestID {
		return nil, fmt.Errorf("request ID mismatch")
	}
	return pdu, nil
}

// GetNext sends an SNMP Get Next Request to the target. Returns the next
// variable response from the OID given or an error
func (c *Client) GetNext(oid string) (*SnmpPacket, error) {
	return c.request(GetNextRequest, oid)
}

// Debug function. Unmarshals raw bytes and returns the result without the network part
func (c *Client) Debug(data []byte) (*SnmpPacket, error) {
	packet, err := Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("unable to decode packet: %v", err)
	}
	return packet, nil
}

// GetBulk sends an SNMP BULK-GET request to the target. Returns a Variable with
// the response or an error
func (c *Client) GetBulk(nonRepeaters, maxRepetitions uint8, oids ...string) (*SnmpPacket, error) {
	// Create and send the packet
	return c.sendPacket(&SnmpPacket{
		Version:        c.Version,
		Community:      c.Community,
		RequestType:    GetBulkRequest,
		NonRepeaters:   nonRepeaters,
		MaxRepetitions: maxRepetitions,
		Variables:      oidsToPbus(oids...),
	})
}

// Get sends an SNMP GET request to the target. Returns a Variable with the
// response or an error
func (c *Client) Get(oids ...string) (*SnmpPacket, error) {
	return c.request(GetRequest, oids...)
}

func (c *Client) request(requestType Asn1BER, oids ...string) (*SnmpPacket, error) {
	return c.sendPacket(&SnmpPacket{
		Version:     c.Version,
		Community:   c.Community,
		RequestType: requestType,
		Variables:   oidsToPbus(oids...),
	})
}

func oidsToPbus(oids ...string) []SnmpPDU {
	pdus := make([]SnmpPDU, len(oids))
	for i, oid := range oids {
		pdus[i] = SnmpPDU{Name: oid, Type: Null}
	}
	return pdus
}
