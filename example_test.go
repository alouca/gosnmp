package gosnmp_test

import (
	"fmt"
	"log"

	snmp "github.com/mwalto7/gosnmp"
)

func ExampleClient_Get() {
	// Create a new SNMP client connection and defer closing the connection.
	client, err := snmp.NewClient("host", "public", snmp.Version2c, 5)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Get the client's sysDescr.0 OID.
	resp, err := client.Get("1.3.6.1.2.1.1.1.0")
	if err != nil {
		log.Fatalf("failed to get oid: %v", err)
	}

	// Loop through the response variables.
	for _, v := range resp.Variables {
		// Handle the SNMP types you expect.
		switch v.Type {
		case snmp.OctetString:
			fmt.Printf("%s: %s = %s\n", v.Name, v.Type.String(), v.Value.([]byte))
		}
	}
}
