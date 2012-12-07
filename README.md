gosnmp
======

GoSNMP is a simple SNMP client library, written fully in Go. Currently
it only supports GetRequest with one or more Oids (varbinds).

It is a rewrite of Andreas Louca's GoSNMP library (alouca/gosnmp) - many
thanks for to him for starting the GoSNMP project. His code is in the
'old' directory.

The code is currently WIP (Work In Progress) - it still has rough edges
and the API's may change.

Sonia Hamilton, sonia@snowfrog.net, http://www.snowfrog.net.

Install
-------

The easiest way to install is via go get:

    go get github.com/soniah/gosnmp

License
-------

Some of the code is from the Golang project as well as alouca/gosnmp,
see the LICENSE file for more details. In general the code is under a
BSD license.

Usage
-----

See examples/walker.go for a more detailed example of usage.

In this snippet, ".1.2.3", ".4.5.6" represent oids.

	s := gosnmp.GoSnmp{
        Target: "192.168.1.10",
        Community: "public",
        Version: gosnmp.NewSnmpVersion("2c"),
        Timeout: 5 * time.Second,
    }
    oids := []string{".1.2.3", ".4.5.6"}           // s.Get() takes one or more oids

    raw_results := s.Get(oids...)                  // undecoded results
    decoded_results := gosnmp.DecodeI(raw_results) // results decoded to Interface{}

    for oid, value := range decoded_results {
        fmt.Printf("oid:%s value:%v\n", oid, value)
    }

Decoders
--------

Get() returns it's results as UnmarshalResults, to give you the
flexibility of implementing your own decoder:

    type Oid string
    type UnmarshalResults map[Oid]asn1.RawValue

One decoder DecodeI() is currently implemented - it decodes to values
that implement Interface{}:

    type DecodeResultsI map[Oid]interface{}
    func DecodeI(ur UnmarshalResults) (dr DecodeResultsI) { ... }

I have also defined (but not implemented) two other decoders:

    // I just want to see string values, like from:
    // snmpget -Oq -On -c public -v 1 192.168.1.10 .1.2.3
    type DecodeResultsS map[Oid]string
    func DecodeS(ur UnmarshalResults) (dr DecodeResultsS) { ... }

    // I just want int64's back - return 0 for non-numeric values
    type DecodeResultsN map[Oid]int64
    func DecodeN(ur UnmarshalResults) (dr DecodeResultsN) { ... }

BER vs DER
----------

SNMP uses BER (Basic Encoding Rules), whereas the golang asn1 package
uses DER (Distinguished Encoding Rules).

DER is is subset (ie stricter) than BER, therefore *sending* SNMP
requests using DER is _kosher_. For *receiving* SNMP results I have
also chosen to use DER rather than BER, with the full expectation that
some results *won't* unmarshal.

Depending on the number of unmarshal errors I get (so far only a
few), I will decide on a direction for handling BER correctly (ie ad-hoc
tweaks versus hacking on asn1).

As asn1/asn1.go says (note the last bit about _very complex_):

    ASN.1 is a syntax for specifying abstract objects and BER, DER, PER, XER etc
    are different encoding formats for those objects. Here, we'll be dealing
    with DER, the Distinguished Encoding Rules. DER is used in X.509 because
    it's fast to parse and, unlike BER, has a unique encoding for every object.
    When calculating hashes over objects, it's important that the resulting
    bytes be the same at both ends and DER removes this margin of error.

    ASN.1 is very complex and this package doesn't attempt to implement
    everything by any means.

Submitting Errors
-----------------

When you get GoSnmp errors due to the BER/DER issue, please email me
with packet dumps suitable for reading by Wireshark.

The easiest way to do this would be to write an examples/config.txt (see
examples/config.in) with the oids that are giving problems, tweak/run
examples/walker.go, then capture in Wireshark using a filter of "udp
port 161 or udp port 162".

See also
--------

* A Layman's Guide to a Subset of ASN.1, BER, and DER, http://luca.ntop.org/Teaching/Appunti/asn1.html
* The Cuddletech Guide to SNMP Programming, http://www.cuddletech.com/articles/snmp/
* Wikipedia X.690, http://en.wikipedia.org/wiki/X.690
* SNMP: Simple? Network Management Protocol, http://www.rane.com/note161.html
