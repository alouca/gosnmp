// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
	"net"
	"time"
)

type GoSnmp struct {
	Target    string
	Community string
	Version   SnmpVersion
	Timeout   time.Duration
	// TODO have a log field, so ppl can initialise with a logger
}

// Get sends an SNMP GET request to the target for one or more oids.
func (s GoSnmp) Get(oids ...string) (ur UnmarshalResults, err error) {
	// this is a library - capture any panics and return as errors
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("gosnmp: %s", e)
		}
	}()

	// initialise
	if len(oids) == 0 {
		return nil, errors.New("gosnmp: Get() requires at least one oid")
	}
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:161", s.Target), s.Timeout)
	if err != nil {
		return nil, fmt.Errorf("gosnmp: Error connecting to socket: %s", err.Error())
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(s.Timeout))

	// marshal & send
	var marshalled_msg []byte
	if marshalled_msg, err = s.Marshal(oids); err != nil {
		return nil, err
	}

	_, err = conn.Write(marshalled_msg)
	if err != nil {
		return nil, fmt.Errorf("gosnmp: Error writing to socket: %s", err.Error())
	}

	// receive & unmarshal
	response := make([]byte, 2048, 2048)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("gosnmp: Error reading from socket: %s", err.Error())
	}
	if ur, err = Unmarshal(response[:n]); err != nil {
		return nil, fmt.Errorf("gosnmp: unmarshal %s", err.Error())
	}
	return
}
