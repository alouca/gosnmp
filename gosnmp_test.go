// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"reflect"
	"testing"
)

var newObjectIdentifierTests = []struct {
	in  string
	out asn1.ObjectIdentifier
	ok  bool
}{
	{".1.3.6.1.4.1.2680.1.2.7.3.2.0", asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 2680, 1, 2, 7, 3, 2, 0}), true},
	{"1.3.6.1.4.1.2680.1.2.7.3.2.0", asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 2680, 1, 2, 7, 3, 2, 0}), true},
	{"", nil, false},
	{"1..3.6.1.4.1..2680.1.2.7.3.2.0", nil, false},
	{"system.sysDescr.0", nil, false},
	{"TimmySaysTimmy!", nil, false},
}

func TestNewObjectIdentifier(t *testing.T) {
	for i, test := range newObjectIdentifierTests {
		ret, err := NewObjectIdentifier(test.in)
		if (err == nil) != test.ok {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.ok)
		}
		if test.ok && !ret.Equal(test.out) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ret, test.out)
		}
	}
}

var withinPercentTests = []struct {
	arg1    interface{}
	arg2    interface{}
	percent float64
	ok      bool
	err     bool
}{
	{"a", "b", float64(1.0), false, true},                  // test all strings
	{int(1.0), "b", float64(1.0), false, true},             // test one string
	{int(0), int(0), float64(1.0), true, false},            // test all zeros
	{int(0), int(1), float64(1.0), false, false},           // test one zero
	{float64(42), float64(42), float64(1.0), true, false},  // test same - floats-like
	{float64(42), float64(50), float64(1.0), false, false}, // test diff - floats-like
	{int(42), int(42), float64(1.0), true, false},          // test same - int-like
	{int(42), int(50), float64(1.0), false, false},         // test diff - int-like
	{uint(42), uint(42), float64(1.0), true, false},        // test same - uint-like
	{uint(42), uint(50), float64(1.0), false, false},       // test diff - uint-like
	{int(42), float64(42), float64(1.0), true, false},      // test same - int-like vs float-like
	{int(42), float64(50), float64(1.0), false, false},     // test diff - int-like vs float-like
	{int(10), int(11), float64(10.0), true, false},         // test within percent
	{int(10), int(12), float64(10.0), false, false},        // test outside percent
}

func TestWithinPercent(t *testing.T) {
	for i, test := range withinPercentTests {
		ok, err := WithinPercent(test.arg1, test.arg2, test.percent)
		// fmt.Printf("i, err: %d, %v\n", i, err)
		if (err != nil) != test.err {
			t.Errorf("#%d: Incorrect error result (did fail? %v, expected: %v)", i, err == nil, test.err)
		}
		if ok != test.ok {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ok, test.ok)
		}
	}
}

var partitionAllPTests = []struct {
	cp int
	ps int
	sl int
	ok bool
}{
	{-1, 3, 8, false}, // test out of range
	{8, 3, 8, false},  // test out of range
	{0, 3, 8, false},  // test 0-7/3 per doco
	{1, 3, 8, false},
	{2, 3, 8, true},
	{3, 3, 8, false},
	{4, 3, 8, false},
	{5, 3, 8, true},
	{6, 3, 8, false},
	{7, 3, 8, true},
}

func TestPartitionAllP(t *testing.T) {
	for i, test := range partitionAllPTests {
		ok := PartitionAllP(test.cp, test.ps, test.sl)
		if ok != test.ok {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, ok, test.ok)
		}
	}
}

var partitionAllTests = []struct {
	in   []interface{}
	size int
	out  [][]interface{}
}{
	{[]interface{}{0, 1, 2, 3, 4, 5, 6, 7}, 3, [][]interface{}{{0, 1, 2}, {3, 4, 5}, {6, 7}}},
	{[]interface{}{'a', 'b', 'c', 'd'}, 2, [][]interface{}{{'a', 'b'}, {'c', 'd'}}},
}

func TestPartitionAll(t *testing.T) {
	for i, test := range partitionAllTests {
		out := PartitionAll(test.in, test.size)
		if !reflect.DeepEqual(out, test.out) {
			t.Errorf("#%d: Bad result: %v (expected %v)", i, out, test.out)
		}
	}
}
