// GoSNMP is a simple SNMP client library, written fully in Go. Currently
// it only supports **GetRequest** with one or more Oids (varbinds).
package gosnmp

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"
)

type GoSnmp struct {
	Target    string        // target - ip addr or hostname
	Community string        // community eg "public"
	Version   SnmpVersion   // Version1 or Version2c
	Timeout   time.Duration // timeout for network connection
	Logger    *log.Logger   // logger for debugging
}

func DefaultGoSnmp(target string) (s *GoSnmp) {
	return &GoSnmp{
		Target:    target,
		Community: "public",
		Version:   Version2c,
		Timeout:   5 * time.Second,
		Logger:    log.New(ioutil.Discard, "", log.LstdFlags),
	}
}

// Get sends an SNMP GET request to the target for one or more oids.
func (s GoSnmp) Get(oids ...string) (ur UnmarshalResults, err error) {
	// this is a library - capture any panics and return as errors
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("gosnmp: %s", e)
		}
	}()

	if err := s.check_parameters(oids); err != nil {
		return nil, err
	}

	// connect
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

// check parameters for sanity
func (s *GoSnmp) check_parameters(oids []string) (err error) {
	var errstr string
	if len(oids) == 0 {
		errstr = errstr + "Get() requires at least one oid, "
	}
	if s.Target == "" {
		errstr = errstr + "a Target is required, "
	}
	if s.Community == "" {
		errstr = errstr + "a Community is required, "
	}
	if s.Timeout == 0 {
		errstr = errstr + "a Timeout is required, "
	}
	if s.Logger == nil {
		errstr = errstr + "a Logger is required (could be ioutil.Discard), "
	}
	if len(errstr) > 0 {
		errstr = errstr[0:len(errstr)-2] + "."
		return fmt.Errorf("gosnmp: %s", errstr)
	}
	return
}
