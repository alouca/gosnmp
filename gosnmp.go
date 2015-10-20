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
	Target     string
	Community  string
	Version    SnmpVersion
	Timeout    time.Duration
	conn       net.Conn
	Log        *l.Logger
	ErrorDelay time.Duration
	RetryCnt   int
}

var DEFAULT_PORT = 161

// Creates a new SNMP Client. Target is the IP address, Community the SNMP Community String and Version the SNMP version.
// Currently only v2c is supported. Timeout parameter is measured in seconds.
func NewGoSNMP(target, community string, version SnmpVersion, timeout int) (*GoSNMP, error) {
	if !strings.Contains(target, ":") {
		target = fmt.Sprintf("%s:%d", target, DEFAULT_PORT)
	}

	// Open a UDP connection to the target
	conn, err := net.DialTimeout("udp", target, time.Duration(timeout)*time.Second)

	if err != nil {
		return nil, fmt.Errorf("Error establishing connection to host: %s\n", err.Error())
	}
	s := &GoSNMP{target, community, version, time.Duration(timeout) * time.Second, conn, l.CreateLogger(false, false), time.Millisecond * 100, 5}
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
func (x *GoSNMP) SetTimeout(seconds int) {
	if seconds <= 0 {
		seconds = 5
	}
	x.Timeout = time.Duration(int64(seconds)) * time.Second
}

// Sets the timeout for network read/write functions. Default to 100ms.
func (x *GoSNMP) SetTimeoutMs(ms int) {
	if ms < 0 {
		ms = 100
	}
	x.Timeout = time.Duration(int64(ms)) * time.Millisecond
}

// Set error delay duration in milliseconds. default to 100. set 0 to disable it.
func (x *GoSNMP) SetErrorDelayMs(ms int) {
	if ms < 0 {
		ms = 100
	}
	x.ErrorDelay = time.Duration(int64(ms)) * time.Millisecond
}

// Set retry cnt limit. default to 5. set 0 to totally disable retry.
func (x *GoSNMP) SetRetryCnt(cnt int) {
	if cnt < 0 {
		cnt = 5
	}
	x.RetryCnt = cnt
}

type StreamWalkResult struct {
	PDU *SnmpPDU
	Err error
}

// StreamWalk will start walking a specified OID, and push through a channel the results
// as it receives them, without waiting for the whole process to finish to return the
// results
func (x *GoSNMP) StreamWalk(oid string, dup_filter_size int) (<-chan *StreamWalkResult, error) {
	if oid == "" {
		return nil, fmt.Errorf("No OID given\n")
	}
	if dup_filter_size <= 0 {
		dup_filter_size = 100
	}

	resChn := make(chan *StreamWalkResult, 0)
	go func() {
		requestOid := oid
		retry_cnt := 0
		old_oids := make([]string, dup_filter_size)
		for {
			x.Log.Debug(" - GetNext: oid: %v", oid)
			if res, err := x.GetNext(oid); err == nil {
				if res == nil {
					resChn <- &StreamWalkResult{nil, fmt.Errorf("nil SnmpPacket")}
					break
				} else {
					if len(res.Variables) > 0 {
						if strings.Index(res.Variables[0].Name, requestOid) > -1 {
							exists := false
							for _, oo := range old_oids {
								if oo == res.Variables[0].Name {
									exists = true
									break
								}
							}
							old_oids = old_oids[:dup_filter_size]
							if exists == false {
								old_oids = append(old_oids, res.Variables[0].Name)
								resChn <- &StreamWalkResult{&res.Variables[0], nil}
								// } else {
								// 	fmt.Printf("duplicated: %v \n", res.Variables[0].Value)
							}
							// Set to the next
							oid = res.Variables[0].Name
							x.Log.Debug("Moving to %s\n", oid)
						} else {
							x.Log.Debug("Root OID mismatch, stopping walk\n")
							break
						}
					} else {
						resChn <- &StreamWalkResult{nil, fmt.Errorf("no SnmpPDU in SnmpPacket.")}
						break
					}
				}
			} else {
				retry_cnt += 1
				if strings.Contains(err.Error(), "i/o timeout") {
					if retry_cnt >= x.RetryCnt {
						er := fmt.Errorf("Reqeust Timeout(%v), After %d Retry. oid: %v", x.Timeout, retry_cnt, oid)
						x.Log.Debug(er.Error())
						resChn <- &StreamWalkResult{nil, er}
						break
					}
					er := fmt.Errorf("Reqeust Timeout(%v), Retry %d. will delay: %v. oid: %v", x.Timeout, retry_cnt, x.ErrorDelay, oid)
					x.Log.Debug(er.Error())
					resChn <- &StreamWalkResult{nil, er}
					time.Sleep(x.ErrorDelay)
					continue
				} else {
					resChn <- &StreamWalkResult{nil, err}
					break
				}
			}
		}
		close(resChn)
		return
	}()
	return resChn, nil
}

func (x *GoSNMP) StreamBulkWalk(max_repetitions uint8, oid string) (<-chan *StreamWalkResult, error) {
	if oid == "" {
		return nil, fmt.Errorf("No OID given\n")
	}

	root_oid := oid
	if strings.HasPrefix(oid, ".") != true {
		root_oid = "." + oid
	}

	var pending_searching_oids = []string{root_oid}
	resChn := make(chan *StreamWalkResult, 0)
	go func() {
		retry_cnt := 0
	loop:
		for len(pending_searching_oids) > 0 {
			sar_oid := pending_searching_oids[0]
			response, err := x.GetBulk(0, max_repetitions, sar_oid)
			if err != nil {
				if strings.Contains(err.Error(), "i/o timeout") {
					retry_cnt += 1
					if retry_cnt >= x.RetryCnt {
						x.Log.Debug("ERROR: GetBulk Timeout(%v) after %d retry. error: delay: %v ", x.Timeout, retry_cnt, x.ErrorDelay)
						resChn <- &StreamWalkResult{nil, fmt.Errorf("ERROR: GetBulk Timeout(%v) after %d retry. error: delay: %v \n", x.Timeout, retry_cnt, x.ErrorDelay)}
						break loop
					}
					x.Log.Debug("Warning: GetBulk Timeout(%v), retry %d, will delay: %v", x.Timeout, retry_cnt, x.ErrorDelay)
					resChn <- &StreamWalkResult{nil, fmt.Errorf("Warning: GetBulk Timeout(%v), retry %d, will delay: %v", x.Timeout, retry_cnt, x.ErrorDelay)}
					time.Sleep(x.ErrorDelay)
					continue
				}
				x.Log.Debug("Warning: error to GetBulk: %v", err)
				resChn <- &StreamWalkResult{nil, fmt.Errorf("Warning: error to GetBulk: %v", err)}
			}

			// shift pending_searching_oids
			pending_searching_oids = pending_searching_oids[1:]

			if response != nil && len(response.Variables) > 0 {
				var last_v *SnmpPDU
				for _, v := range response.Variables {
					vv := v // copy is needed here.
					if strings.HasPrefix(v.Name, root_oid) {
						// sometimes, pdu at response.Variables[-1] has a different prefix. so we have to keep every last v which has the
						// root_oid as it's prefix.
						last_v = &vv
						resChn <- &StreamWalkResult{&vv, nil}
					}
				}
				if last_v != nil {
					pending_searching_oids = append(pending_searching_oids, last_v.Name)
				}
			}
		}
		close(resChn)
		return
	}()
	return resChn, nil
}

func (x *GoSNMP) BulkWalk(max_repetitions uint8, oid string) (results []SnmpPDU, err error) {
	if oid == "" {
		return nil, fmt.Errorf("No OID given\n")
	}

	root_oid := oid
	if strings.HasPrefix(oid, ".") != true {
		root_oid = "." + oid
	}

	var pending_searching_oids = []string{root_oid}

	retry_cnt := 0
	for len(pending_searching_oids) > 0 {
		sar_oid := pending_searching_oids[0]
		response, err := x.GetBulk(0, max_repetitions, sar_oid)
		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") {
				retry_cnt += 1
				if retry_cnt >= x.RetryCnt {
					x.Log.Debug("ERROR: GetBulk Timeout(%v) after %d retry. error: delay: %v ", x.Timeout, retry_cnt, x.ErrorDelay)
					return results, fmt.Errorf("ERROR: GetBulk Timeout(%v) after %d retry. error: delay: %v \n", x.Timeout, retry_cnt, x.ErrorDelay)
				}
				x.Log.Debug("Warning: GetBulk Timeout(%v), retry %d, will delay: %v", x.Timeout, retry_cnt, x.ErrorDelay)
				time.Sleep(x.ErrorDelay)
				continue
			}
			x.Log.Debug("Warning: error to GetBulk: %v", err)
		}

		// shift pending_searching_oids
		pending_searching_oids = pending_searching_oids[1:]

		if response != nil && len(response.Variables) > 0 {
			var last_v *SnmpPDU
			for _, v := range response.Variables {
				if strings.HasPrefix(v.Name, root_oid) {
					// sometimes, pdu at response.Variables[-1] has a different prefix. so we have to keep every last v which has the
					// root_oid as it's prefix.
					last_v = &v
					results = append(results, v)
				}
			}
			if last_v != nil {
				pending_searching_oids = append(pending_searching_oids, last_v.Name)
			}
		}
	}
	return
}

// Walk will SNMP walk the target, blocking until the process is complete
func (x *GoSNMP) Walk(oid string) (results []SnmpPDU, err error) {
	if oid == "" {
		return nil, fmt.Errorf("No OID given\n")
	}
	results = make([]SnmpPDU, 0)
	requestOid := oid

	for {
		res, err := x.GetNext(oid)
		if err != nil {
			return results, err
		}
		if res != nil {
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
	resp := make([]byte, 8192, 8192)
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

// Sends an SNMP BULK-GET request to the target. Returns a Variable with the response or an error
func (x *GoSNMP) GetBulk(non_repeaters, max_repetitions uint8, oids ...string) (*SnmpPacket, error) {
	var err error
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()

	// Create the packet
	packet := new(SnmpPacket)

	packet.Community = x.Community
	packet.NonRepeaters = non_repeaters
	packet.MaxRepetitions = max_repetitions
	packet.RequestType = GetBulkRequest
	packet.Version = 1 // version 2
	packet.Variables = make([]SnmpPDU, len(oids))

	for i, oid := range oids {
		packet.Variables[i] = SnmpPDU{Name: oid, Type: Null}
	}

	return x.sendPacket(packet)
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
