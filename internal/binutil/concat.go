// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package binutil

import (
	"fmt"
	"math"
)

// Concat accumulates byte slices and supports the alignment behavior used by
// Crystal Palace's binary formatters.
type Concat struct {
	values     [][]byte
	total      int
	virtualPad int
}

// NewConcat creates an accumulator and optionally adds initial data.
func NewConcat(initial ...[]byte) (*Concat, error) {
	concat := &Concat{}
	for _, data := range initial {
		if err := concat.Add(data); err != nil {
			return nil, err
		}
	}
	return concat, nil
}

// Add appends a byte slice. As upstream, the slice is observed when Bytes is
// called rather than cloned at Add time.
func (c *Concat) Add(data []byte) error {
	if c.total > math.MaxInt-c.virtualPad || len(data) > math.MaxInt-c.total-c.virtualPad {
		return fmt.Errorf("concatenated size overflows int")
	}
	c.values = append(c.values, data)
	c.total += len(data)
	return nil
}

// AddByte appends one byte.
func (c *Concat) AddByte(value byte) error { return c.Add([]byte{value}) }

// Pad adds virtual padding to Length. This intentionally preserves the
// upstream Concat contract: virtual padding affects later alignment but is not
// itself materialized by Bytes. Binary zero padding should normally use Align.
func (c *Concat) Pad(count int) error {
	if count < 0 || c.total > math.MaxInt-c.virtualPad || count > math.MaxInt-c.virtualPad-c.total {
		return fmt.Errorf("invalid virtual padding %d", count)
	}
	c.virtualPad += count
	return nil
}

// Align appends NUL bytes until Length is aligned to boundary.
func (c *Concat) Align(boundary int) error {
	if boundary <= 0 {
		return fmt.Errorf("alignment must be positive: %d", boundary)
	}
	remainder := c.Length() % boundary
	if remainder == 0 {
		return nil
	}
	return c.Add(make([]byte, boundary-remainder))
}

// Length returns the upstream logical length, including virtual Pad calls.
func (c *Concat) Length() int { return c.total + c.virtualPad }

// Bytes materializes the accumulated data. Virtual Pad calls are deliberately
// excluded for compatibility with upstream Concat.get().
func (c *Concat) Bytes() []byte {
	result := make([]byte, c.total)
	offset := 0
	for _, value := range c.values {
		copy(result[offset:], value)
		offset += len(value)
	}
	return result
}
