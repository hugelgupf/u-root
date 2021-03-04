// Copyright 2020 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uflag

import "strings"

// Strings implements flag.Value that appends multiple invocations of the
// flag to a slice of strings.
type Strings []string

// Set implements flag.Value.Set.
func (s *Strings) Set(value string) error {
	if len(value) > 0 {
		*s = append(*s, value)
	}
	return nil
}

// String implements flag.Value.String.
func (s Strings) String() string {
	return strings.Join(s, ",")
}

// Get implements google3/base/go/flag.Value.Get.
func (s Strings) Get() interface{} {
	return []string(s)
}
