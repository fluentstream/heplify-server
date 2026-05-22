// Copyright 2011, Shelby Ramsey. All rights reserved.
// Copyright 2018, Eugen Biegler. All rights reserved.
// Use of this code is governed by a BSD license that can be
// found in the LICENSE.txt file.

package sipparser

// Imports from the go standard library
import (
	"testing"
)

func TestCseq(t *testing.T) {
	sm := &SipMsg{}
	sm.parseCseq("100 INVITE")
	if sm.Error != nil {
		t.Errorf("[TestCseq] Error parsing cseq: \"100 INVITE\". Received err: %v", sm.Error)
	}
	if sm.Cseq.Digit != "100" {
		t.Errorf("[TestCseq] Error parsing cseq: \"100 INVITE\".  Digit should be 100.")
	}
	if sm.Cseq.Method != "INVITE" {
		t.Errorf("[TestCseq] Error parsing cseq: \"100 INVITE\".  Method should be \"INVITE\".")
	}
	sm.parseCseq("1112423100   REGISTER   ")
	if sm.Error != nil {
		t.Errorf("[TestCseq] Error parsing cseq: \"1112423100   REGISTER   \". Received err: %v", sm.Error)
	}
	if sm.Cseq.Digit != "1112423100" {
		t.Errorf("[TestCseq] Error parsing cseq: \"1112423100   REGISTER   \".  Digit should be 1112423100.")
	}
	if sm.Cseq.Method != "REGISTER" {
		t.Errorf("[TestCseq] Error parsing cseq: \"1112423100   REGISTER   \".  Method should be \"REGISTER\".")
	}
}

// TestCseqMalformedSanitizes exercises the validMethodToken truncation
// path against the actual corruption patterns observed on the wire from
// internet-facing capture: bare CR/LF/NUL bytes embedded in CSeq method
// values that previously leaked into Prometheus labels and broke strict
// scrapers (Datadog OpenMetrics).
func TestCseqMalformedSanitizes(t *testing.T) {
	cases := []struct {
		name       string
		val        string
		wantMethod string
		wantErr    bool
	}{
		{name: "trailing CR", val: "1234 SUBSCRIBE\rE", wantMethod: "SUBSCRIBE"},
		{name: "trailing LF", val: "5678 NOTIFY\nfoo", wantMethod: "NOTIFY"},
		{name: "embedded NUL", val: "9 INVITE\x00garbage", wantMethod: "INVITE"},
		{name: "trailing space (legitimate)", val: "10 SUBSCRIBE ", wantMethod: "SUBSCRIBE"},
		{name: "extension method", val: "1 X-CUSTOM-METHOD", wantMethod: "X-CUSTOM-METHOD"},
		{name: "method starting with digit", val: "1 2ABC", wantMethod: "2ABC"},
		{name: "pure garbage", val: "1 \x01\x02", wantErr: true},
		{name: "empty after digits and space", val: "1 ", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Cseq{Val: tc.val}
			err := c.parse()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got method=%q", c.Method)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Method != tc.wantMethod {
				t.Errorf("method=%q, want %q", c.Method, tc.wantMethod)
			}
		})
	}
}
