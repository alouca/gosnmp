gosnmp
======

GoSNMP is a simple SNMP client library, written fully in Go. Currently
it only supports **GetRequest** with one or more Oids (varbinds).

It is a rewrite of Andreas Louca's GoSNMP library
[alouca/gosnmp](https://github.com/alouca/gosnmp) - many thanks for to
him for starting the GoSNMP project.

The code is currently WIP (Work In Progress) - it still has rough edges
and the API's may (will) change.

Sonia Hamilton, sonia@snowfrog.net, http://www.snowfrog.net.

**See also:** http://godoc.org/github.com/soniah/gosnmp

Install
-------

The easiest way to install is via **go get**:

    go get github.com/soniah/gosnmp

License
-------

Some of the code is from the Golang project as well as alouca/gosnmp,
see the LICENSE file for more details. In general the code is under a
BSD license.

Usage
-----

See **examples/walker.go** for a more detailed example of usage. In this snippet,
**".1.2.3"**, **".4.5.6"** represent valid oids.

```go
import "github.com/soniah/gosnmp"

// defaults: public, 2c, 5s timeout, discard logging
s := gosnmp.DefaultGoSNMP("192.168.1.10")         // target ip address/hostname

// change some default values
s.Logger = log.New(os.Stderr, "", log.LstdFlags)  // log GoSnmp internals
s.Timeout = 60 * time.Second                      // target is slow

// or, use a struct initialiser
s := &gosnmp.GoSnmp{
	Target:    "10.0.0.10",
	Community: "private",
	Version:   gosnmp.Version1,
	Timeout:   2 * time.Second,
	Logger:    log.New(ioutil.Discard, "", log.LstdFlags),      // no logging
}

ur := s.Get(".1.2.3")                             // s.Get takes one
ur := s.Get(".1.2.3", ".4.5.6")                   // or more
oids := []string{".1.2.3", ".4.5.6"}              // or more
ur := s.Get(oids...)                              // or more oids
```

**Get** returns it's results as **UnmarshalResults**, to give you the
flexibility of implementing your own decoder:

    type UnmarshalResults map[Oid]asn1.RawValue

    type Oid string

Decoders
--------

One decoder **FullDecode** is currently implemented - it does a full decode
suitable for testing/debugging:

    type FullResult struct {
        Value Taggish
        Debug string // debugging messages
        Error error  // decoding errors, not "No Such Object", "Null", etc
    }

    type Taggish interface {
        Integer() int64
        fmt.Stringer
    }

    type FullDecodeResults map[Oid]*FullResult

    func (s GoSnmp) FullDecode(ur UnmarshalResults) (r FullDecodeResults) { ... }

    // for example
    fd := s.FullDecode(ur)
    for oid, rv := range ur {

        fmt.Println("oid:", oid)

        // raw value received from unmarshal
        log.Printf("raw_value: %#v", rv)

        full_result := fd[oid]

        // tag type, eg TagResultOctetString, TagResultCounter32
        fmt.Println("interface type:", reflect.TypeOf(full_result.Value))

        // I just want my result as a string
        fmt.Printf("string decode: %s", full_result.Value)

        // I just want my result as a number
        fmt.Printf("int decode: %d", full_result.Value.Integer())
    }

You may want to implement your own smaller/faster decoder based on
**FullDecode**.

Helper Functions
----------------

There are a number of helper functions in **common.go**. Many of these have
tests that serve as example usage; see also **examples/walker.go**.

**NewObjectIdentifier** - make a new asn1.ObjectIdentifier from an oid in
string form.

    func NewObjectIdentifier(oid string) (result asn1.ObjectIdentifier, err error) { ... }

**PartitionAll** - partition a slice into multiple slices of given
length, with the last item possibly being of smaller length.

    func PartitionAll(slice []interface{}, partition_size int) (result [][]interface{}) { ... }

A use case for **PartitionAll** is you have a 'bazillion' oids to retrieve for
a single device. You could:

* send all bazillion oids in one **s.Get** - brave
* do an **s.Bulkwalk** - but I haven't implemented that yet, and maybe
  your target device only supports SNMP v1 anyway

Instead, you could do:

    oidss := []string{".1.2.3", ".4.5.6", ...... }   // a bazillion oids
    for oids := range PartitionAll(oidss, 500) {     // value 500 will vary
        ur := s.Get(oids...)
        // process ur
    }

**PartitionAllP** - helper function for **PartitionAll**, but also
useful by itself for dividing a slice into partitions.

    func PartitionAllP(current_position, partition_size, slice_length int) bool { ... }

**WithinPercent** - for testing if numeric values returned by snmpget
(or anything really) are within a certain percentage of each other.

    func WithinPercent(arg1, arg2 interface{}, percent float64) (bool, error) { ... }

BER vs DER
----------

SNMP uses **BER** (Basic Encoding Rules), whereas the golang asn1 package
uses **DER** (Distinguished Encoding Rules).

DER is a subset of (ie stricter) than BER, therefore **sending** SNMP
requests using DER is _ok_. For **receiving** SNMP results I have
also chosen to use DER rather than BER, with the full expectation that
some results **won't** unmarshal.

Depending on the number of unmarshal errors I get (so far only a
few), I will decide on a direction for handling BER correctly (ie ad-hoc
tweaks versus hacking on asn1).

As **asn1/asn1.go** says (note the last bit about _very complex_):

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

The easiest way to do this would be to write an **examples/config.txt** (see
**examples/config.in**) with the oids that are giving problems, tweak/run
**examples/walker.go**, then capture in Wireshark using a filter of **udp
port 161 or udp port 162**.

See also
--------

* A Layman's Guide to a Subset of ASN.1, BER, and DER, http://luca.ntop.org/Teaching/Appunti/asn1.html
* The Cuddletech Guide to SNMP Programming, http://www.cuddletech.com/articles/snmp/
* Wikipedia X.690, http://en.wikipedia.org/wiki/X.690
* SNMP: Simple? Network Management Protocol, http://www.rane.com/note161.html
