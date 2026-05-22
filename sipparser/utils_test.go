// Copyright 2011, Shelby Ramsey. All rights reserved.
// Copyright 2018, Eugen Biegler. All rights reserved.
// Use of this code is governed by a BSD license that can be
// found in the LICENSE.txt file.

package sipparser

import (
	"testing"
)

func TestCleanWs(t *testing.T) {
	s := "     white space	"
	if cleanWs(s) != "white space" {
		t.Errorf("[TestCleanWs] Error from cleanWs.  Got unexpected result.")
	}
	s = "	" // tab
	if cleanWs(s) != "" {
		t.Errorf("[TestCleanWs] Error from cleanWs.  Got unexpected result.")
	}
}

func TestValidMethodToken(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain method", "INVITE", "INVITE"},
		{"trailing CR", "SUBSCRIBE\rE", "SUBSCRIBE"},
		{"trailing LF", "NOTIFY\n", "NOTIFY"},
		{"embedded NUL", "INVITE\x00garbage", "INVITE"},
		{"all garbage", "\x01\x02\x03", ""},
		{"extension method with hyphen", "X-CUSTOM-METHOD", "X-CUSTOM-METHOD"},
		{"non-alpha start (digit)", "2ABC", "2ABC"},
		{"all token punct", "abc.+-!%*_+`'~", "abc.+-!%*_+`'~"},
		{"space terminates token", "INVITE foo", "INVITE"},
		{"trailing tab", "BYE\t", "BYE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validMethodToken(tc.in)
			if got != tc.want {
				t.Errorf("validMethodToken(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCleanBrack(t *testing.T) {
	s := "<sip:foo@bar.com>"
	if cleanBrack(s) != "sip:foo@bar.com" {
		t.Errorf("[TestCleanBrack] Error cleaning bracks from \"<sip:foo@bar.com>\".")
	}
	s = "<sip:foo@bar.com>;param=foo?header=boo"
	if cleanBrack(s) != "sip:foo@bar.com;param=foo?header=boo" {
		t.Errorf("[TestCleanBrack] Error cleaning bracks from \"<sip:foo@bar.com>;param=foo?header=boo\".")
	}
}

func TestGetName(t *testing.T) {
	s := "\"name\" <sip:foo@bar.com>"
	name, _ := getName(s)
	if name != "name" {
		t.Errorf("[TestGetName] Error getting name from getName for:  \"name\" <sip:foo@bar.com>")
	}
	s = "<sip:foo@bar.com>"
	name, _ = getName(s)
	if name != "" {
		t.Errorf("[TestGetName] Received a name for a string without one from getName.")
	}
	s = "Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8"
	name, _ = getName(s)
	if name != "Anonymous" {
		t.Errorf("[TestGetName] Error parsing string: Anonymous <sip:c8oqz84zk7z@privacy.org>;tag=hyh8.  Should have gotten name: \"Anonymous\" but received: \"%s\".", name)
	}
}

func TestGetCommaSeperated(t *testing.T) {
	s := "foo "
	cs := getCommaSeperated(s)
	if cs != nil {
		t.Errorf("[TestGetCommaSeperated] Error with string: \"foo\".  getCommaSeperated should have returned nil.")
	}
	s = "foo , bar"
	cs = getCommaSeperated(s)
	if cs == nil {
		t.Errorf("[TestGetCommaSeperated] Error with string: \"foo , bar\".  getCommaSeperated should have returned a list of strings.  Returned nil.")
	}
	if len(cs) != 2 {
		t.Errorf("[TestGetCommaSeperated] Error with string: \"foo , bar\".  Returned list but length should be 2.")
	}
	if cs[0] != "foo" {
		t.Errorf("[TestGetCommaSeperated] Error with string: \"foo , bar\".  Returned list pos[0] should be \"foo\" but received: " + cs[0])
	}
	if cs[1] != "bar" {
		t.Errorf("[TestGetCommaSeperated] Error with string: \"foo , bar\".  Returned list pos[1] should be \"bar\" but received: " + cs[1])
	}
}
