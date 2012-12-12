gosnmp
======

GoSNMP is a simple SNMP client library, written fully in Go. Currently
it only supports **GetRequest** with one or more Oids (varbinds).

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

See **examples/walker.go** for a more detailed example of usage. In this snippet,
**".1.2.3"**, **".4.5.6"** represent valid oids.

    // defaults: public, 2c, 5s timeout, discard logging
    s := DefaultGoSNMP("192.168.1.10")                // target ip address/hostname

    // change some default values
    s.Logger = log.New(os.Stderr, "", log.LstdFlags)  // log GoSnmp internals
    s.Timeout = 60 * time.Second                      // target is slow

    ur := s.Get(".1.2.3")                             // s.Get() takes one
    // ur := s.Get(".1.2.3", ".4.5.6")                // or more
    // oids := []string{".1.2.3", ".4.5.6"}           // or more
    // ur := s.Get(oids...)                           // oids

**Get()** returns it's results as **UnmarshalResults**, to give you the
flexibility of implementing your own decoder:

    // type Oid string
    // type UnmarshalResults map[Oid]asn1.RawValue

    fd := s.FullDecode(ur)
    for oid, rv := range ur {
        log.Printf("raw_value: %#v\n", rv)
        log.Printf("oid|decode: %s|%#v\n\n", oid, fd[oid])
    }

Decoders
--------

One decoder **FullDecode()** is currently implemented - it does a full decode
suitable for testing/debugging:

    type FullResult struct {
        Value Taggish
        Debug string // any debugging messages
        Error error  // any errors in decoding
    }

    type Taggish interface {
        String() string
        Integer() int64
    }

    type FullDecodeResults map[Oid]*FullResult

    func (s GoSnmp) FullDecode(ur UnmarshalResults) (r FullDecodeResults) { ... }


You may want to implement your own smaller/faster decoder based on
**FullDecode()**.
