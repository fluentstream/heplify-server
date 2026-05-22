// Copyright 2011, Shelby Ramsey. All rights reserved.
// Copyright 2018, Eugen Biegler. All rights reserved.
// Use of this code is governed by a BSD license that can be
// found in the LICENSE.txt file.

package sipparser

// Imports from the go standard library
import (
	"fmt"
	"strings"
)

// Cseq is a struct that holds the values for a cseq header:
//
//	-- Val is the raw string value of the cseq hdr
//	-- Method is the SIP method
//	-- Digit is the numeric indicator for the method
type Cseq struct {
	Val    string
	Method string
	Digit  string
}

func (c *Cseq) parse() error {
	if len(c.Val) < 3 {
		return fmt.Errorf("Cseq.parse err: length of CSeq is < 3")
	}
	s := strings.IndexRune(c.Val, ' ')
	if s == -1 {
		return fmt.Errorf("Cseq.parse err: lws err with: %q", c.Val)
	}
	if s == 0 {
		return fmt.Errorf("Cseq.parse err: lws at pos 0 in val: %q", c.Val)
	}
	if len(c.Val)-1 < s+1 {
		return fmt.Errorf("Cseq.parse err: first lws is end of line in val: %q", c.Val)
	}
	c.Digit = c.Val[0:s]
	var raw string
	if c.Val[s+1] != ' ' {
		raw = c.Val[s+1:]
	} else {
		raw = cleanWs(c.Val[s+1:])
	}
	// Truncate at the first non-token byte (RFC 3261 §25.1) to defang
	// stray CR/LF/NUL/etc. coming from malformed upstream SIP. The
	// truncated prefix still represents what the wire said within the
	// bounds of valid token grammar; arbitrary garbage that doesn't even
	// start with a token byte is rejected outright.
	c.Method = validMethodToken(raw)
	if c.Method == "" {
		return fmt.Errorf("Cseq.parse err: invalid or empty method token in val: %q", c.Val)
	}
	return nil
}
