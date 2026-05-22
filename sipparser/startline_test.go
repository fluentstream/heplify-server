// Copyright 2011, Shelby Ramsey. All rights reserved.
// Copyright 2018, Eugen Biegler. All rights reserved.
// Use of this code is governed by a BSD license that can be
// found in the LICENSE.txt file.

package sipparser

// Imports from the go standard library
import (
	"testing"
)

func TestStartLine(t *testing.T) {
	str := "SIP/2.0 487 Request Cancelled"
	s := &StartLine{Val: str}
	s.run()
	if s.Type != SIP_RESPONSE {
		t.Error("[TestStartLine] Error parsing startline: SIP/2.0 487 Request Cancelled.  s.Type should be \"RESPONSE\".")
	}
	if s.Resp != "487" {
		t.Error("[TestStartLine] Error parsing startline: SIP/2.0 487 Request Cancelled.  s.Resp should be \"487\".")
	}
	if s.RespText != "Request Cancelled" {
		t.Error("[TestStartLine] Error parsing startline: SIP/2.0 487 Request Cancelled.  s.RespText should be \"Request Cancelled\".")
	}
	str = "SIP/2.0 500"
	s = &StartLine{Val: str}
	s.run()
	if s.Type != SIP_RESPONSE {
		t.Error("[TestStartLine] Error parsing startline: SIP/2.0 500.  s.Type should be \"RESPONSE\".")
	}
	if s.Resp != "500" {
		t.Error("[TestStartLine] Error parsing startline: SIP/2.0 500.  s.Resp should be \"500\".")
	}
	if s.RespText != "" {
		t.Error("[TestStartLine] Error parsing startline: SIP/2.0 500.  s.RespText should be \"\".")
	}
	str = "1412@34922@336312786@1.2.3.4:5061;transport=tcp;user=phone@home1.2.3.4                                            111111111"
	s = ParseStartLine(str)
	if s.Error == nil {
		t.Error("[TestStartLine] Error parsing startline.  s.Error should not be nil.")
	}
	str = "dlskmgkfmdg ldf,l,"
	s = ParseStartLine(str)
	if s.Error == nil {
		t.Error("[TestStartLine] Error parsing startline.  s.Error should not be nil for string: \"dlskmgkfmdg ldf,l,\".")
	}
	str = "INVITE sip:+15554440000@0.0.0.0;user=phone SIP/2.0"
	s = ParseStartLine(str)
	if s.Error != nil {
		t.Errorf("[TestStartLine] Got error when parsing startline: \"INVITE sip:+15554440000@0.0.0.0;user=phone SIP/2.0\".  Received err: %v", s.Error)
	}
	if s.Type != SIP_REQUEST {
		t.Error("[TestStartLine] Got error when parsing startline: \"INVITE sip:+15554440000@0.0.0.0;user=phone SIP/2.0\".  s.Type should be \"Request\".")
	}
	if s.Method != SIP_METHOD_INVITE {
		t.Error("[TestStartLine] Got error when parsing startline: \"INVITE sip:+15554440000@0.0.0.0;user=phone SIP/2.0\".  s.Method should be \"INVITE\".")
	}
	if s.Proto != "SIP" {
		t.Errorf("[TestStartLine] Got error when startline: \"INVITE sip:+15554440000@0.0.0.0;user=phone SIP/2.0\".  s.Proto should be \"SIP\".  Received: \"%s\"", s.Proto)
	}
	if s.Version != "2.0" {
		t.Errorf("[TestStartLine] Got error when parsing startline: \"INVITE sip:+15554440000@0.0.0.0;user=phone SIP/2.0\".  s.Version should be \"2.0\". Received: \"%s\"", s.Version)
	}
	// throwing this in to make sure we don't toss an index error
	str = "INVITE foo@bar.com SIP/"
	s = ParseStartLine(str)
	if s.Error == nil {
		t.Error("[TestStartLine] Should have a no version err when parsing request line: \"INVITE foo@bar.com SIP/\".")
	}
}

func TestStartLineRequestMalformedMethod(t *testing.T) {
	cases := []struct {
		name       string
		val        string
		wantMethod string
		wantErr    bool
	}{
		{
			name:       "trailing CR in method",
			val:        "INVITE\rE sip:alice@example.com SIP/2.0",
			wantMethod: "INVITE",
		},
		{
			name:       "trailing NUL in method",
			val:        "REGISTER\x00 sip:alice@example.com SIP/2.0",
			wantMethod: "REGISTER",
		},
		{
			name:       "extension method",
			val:        "X-CUSTOM-METHOD sip:alice@example.com SIP/2.0",
			wantMethod: "X-CUSTOM-METHOD",
		},
		{
			name:    "pure garbage method",
			val:     "\x01\x02 sip:alice@example.com SIP/2.0",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ParseStartLine(tc.val)
			if tc.wantErr {
				if s.Error == nil {
					t.Fatalf("expected error, got method=%q", s.Method)
				}
				return
			}
			if s.Error != nil {
				t.Fatalf("unexpected error: %v", s.Error)
			}
			if s.Method != tc.wantMethod {
				t.Errorf("method=%q, want %q", s.Method, tc.wantMethod)
			}
		})
	}
}

func TestStartLineResponseValidates(t *testing.T) {
	cases := []struct {
		name     string
		val      string
		wantResp string
		wantErr  bool
	}{
		{name: "standard 200 OK", val: "SIP/2.0 200 OK", wantResp: "200"},
		{name: "100 Trying", val: "SIP/2.0 100 Trying", wantResp: "100"},
		{name: "699 boundary", val: "SIP/2.0 699 Custom", wantResp: "699"},
		{name: "code with no text", val: "SIP/2.0 481", wantResp: "481"},
		{name: "code 099 (sub-100)", val: "SIP/2.0 099 Bogus", wantErr: true},
		{name: "code 700 (over-600)", val: "SIP/2.0 700 Bogus", wantErr: true},
		{name: "non-numeric code", val: "SIP/2.0 ABC Bogus", wantErr: true},
		{name: "two-digit code", val: "SIP/2.0 20 OK", wantErr: true},
		{name: "four-digit code", val: "SIP/2.0 2000 OK", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := ParseStartLine(tc.val)
			if tc.wantErr {
				if s.Error == nil {
					t.Fatalf("expected error, got resp=%q", s.Resp)
				}
				return
			}
			if s.Error != nil {
				t.Fatalf("unexpected error: %v", s.Error)
			}
			if s.Resp != tc.wantResp {
				t.Errorf("resp=%q, want %q", s.Resp, tc.wantResp)
			}
		})
	}
}
