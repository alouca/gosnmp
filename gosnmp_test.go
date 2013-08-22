package gosnmp

import (
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	TestPackets []string = []string{
		"3082003202010104067075626c6963a28200230201000201000201003082001630820012060a2b060102010202010a02410409b3fe85",
		//	"30820132020101040977767370645f345f5fa28201200204264a86e6020100020100308201103082010c06082b060102010101000481ff436973636f20494f5320536f6674776172652c20633736303072737037323034335f727020536f6674776172652028633736303072737037323034335f72702d414456495053455256494345534b392d4d292c2056657273696f6e2031352e3328312953312c2052454c4541534520534f4654574152452028666331290d0a546563686e6963616c20537570706f72743a20687474703a2f2f7777772e636973636f2e636f6d2f74656368737570706f72740d0a436f707972696768742028632920313938362d3230313320627920436973636f2053797374656d732c20496e632e0d0a436f6d70696c6564205468752030372d4665622d31332030363a32",
		//	"307b020101040977767370645f345f5fa26b020431b6dfa5020100020100305d305b06082b06010201010100044f4c696e757820646e733120322e362e33322d34352d73657276657220233130342d5562756e747520534d5020547565204665622031392032313a33353a3031205554432032303133207838365f3634",
		//	"3036020101040977767370645f345f5fa2260204662322fa02010002010030183016060c2b060102011f0101010a8206460619ed7896f6e0",
		//	"3081ce02010104067075626c6963a281c0020408659d0c0201000201003081b13012060a2b060102010202010a02410400f34d353012060a2b060102010202010a03410401119cc3300f060a2b060102010202010a04410100300f060a2b060102010202010a05410100300f060a2b060102010202010a06410100300f060a2b060102010202010a07410100300f060a2b060102010202010a08410100300f060a2b060102010202010a09410100300f060a2b060102010202010a0a4101003010060a2b060102010202010a1041020a59",
	}
)

func BenchmarkUnmarshal(t *testing.B) {
	t.Log("Running Decode Benchmark\n")
	packet, _ := hex.DecodeString(TestPackets[0])
	s, _ := NewGoSNMP("", "", Version2c, 5)
	for i := 0; i < t.N; i++ {
		s.Debug(packet)
	}
}

func TestDecode(t *testing.T) {
	t.Log("Running Decode Test\n")
	s, _ := NewGoSNMP("", "", Version2c, 5)
	s.SetDebug(true)
	s.SetVerbose(true)

	for _, p := range TestPackets {
		packet, err := hex.DecodeString(p)
		if err != nil {
			t.Errorf("Unable to decode raw packet: %s\n", err.Error())
			return
		}

		pckt, err := s.Debug(packet)

		if err != nil {
			fmt.Printf("Error while debugging: %s\n", err.Error())
		} else {
			for _, resp := range pckt.Variables {
				fmt.Printf("%s -> %v\n", resp.Name, resp.Value)
			}
		}

	}
}

func TestWalk(t *testing.T) {
	t.Log("Running walk test")
	s, _ := NewGoSNMP("sample", "demo", Version2c, 5)
	s.SetDebug(true)
	s.SetVerbose(true)
	res, err := s.Walk(".1.3.6.1.2.1.2")

	if err != nil {
		t.Fatalf("Unable to perform walk: %s\n", err.Error())
	} else {
		for i, r := range res {
			t.Logf("%d: %s -> %v", i, r.Name, r.Value)
		}
	}

}

// Test SNMP connections with different ports
func TestConnect(t *testing.T) {
        t.Log("Running connection tests")
        targets := []string{"localhost", "localhost:161"}

        for _, target := range targets {
                _, err := NewGoSNMP(target, "public", Version2c, 5)

                if err != nil {
                        t.Fatalf("Unable to connect to %s: %s\n", target, err)
                }
        }
}

// Test Data Type stringer
func TestDataTypeStrings(t *testing.T) {
	var dataType Asn1BER

	// Defined data type
	dataType = Integer

	if dataType.String() != "Integer" {
		t.Errorf("Data Type strings:\n\twant: %q\n\tgot : %q", "Integer", dataType)
	}

	// Undefined data type
	dataType = 0x00

	if dataType.String() != "Unknown" {
		t.Errorf("Data Type strings:\n\twant: %q\n\tgot : %q", "Integer", dataType)
	}
}
