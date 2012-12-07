// Copyright 2012 Sonia Hamilton <sonia@snowfrog.net>. All rights
// reserved.  Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
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
