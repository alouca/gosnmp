// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"github.com/alouca/gosnmp"
	"strings"
)

var (
	cmdCommunity string
	cmdTarget    string
	cmdOid       string
	cmdDebug     string
	cmdTimeout   int64
)

func init() {
	flag.StringVar(&cmdDebug, "debug", "", "Debug flag expects byte array of raw packet to test decoding")

	flag.StringVar(&cmdTarget, "target", "", "Host SNMP Agent")
	flag.StringVar(&cmdCommunity, "community", "public", "SNNP Community")
	flag.StringVar(&cmdOid, "oid", "", "The request OID. Multiple OIDs can be separated by a comma")
	flag.Int64Var(&cmdTimeout, "timeout", 5, "Set the timeout in seconds")
	flag.Parse()
}

func main() {
	if cmdTarget == "" || cmdOid == "" {
		flag.PrintDefaults()
		return
	}

	s, err := gosnmp.NewGoSNMP(cmdTarget, cmdCommunity, gosnmp.Version2c, cmdTimeout)
	if cmdDebug == "yes" {
		s.SetDebug(true)
		s.SetVerbose(true)
	}
	if err != nil {
		fmt.Printf("Error creating SNMP instance: %s\n", err.Error())
		return
	}

	s.SetTimeout(cmdTimeout)
	fmt.Printf("Getting %s\n", cmdOid)
	oid := strings.Split(cmdOid, ",")
	resp, err := s.GetMulti(oid)
	if err != nil {
		fmt.Printf("Error getting response: %s\n", err.Error())
	} else {
		for _, v := range resp.Variables {
			fmt.Printf("%s -> ", v.Name)
			switch v.Type {
			case gosnmp.OctetString:
				if s, ok := v.Value.(string); ok {
					fmt.Printf("%s\n", s)
				} else {
					fmt.Printf("Response is not a string\n")
				}
			default:
				fmt.Printf("Type: %d - Value: %v\n", v.Type, v.Value)
			}
		}

	}

}
