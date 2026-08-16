// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package hookresolve

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type boundedRandom interface {
	nextInt(int) (int, int, error)
}

type readerRandom struct{ reader io.Reader }

func (r readerRandom) nextInt(bound int) (int, int, error) {
	if bound <= 0 {
		return 0, 0, errors.New("non-positive random bound")
	}
	draws := 0
	for {
		var data [4]byte
		if _, err := io.ReadFull(r.reader, data[:]); err != nil {
			return 0, draws, fmt.Errorf("read randomness: %w", err)
		}
		draws++
		bits := int32(binary.BigEndian.Uint32(data[:]) & 0x7fffffff)
		if bound&(bound-1) == 0 {
			return int((int64(bound) * int64(bits)) >> 31), draws, nil
		}
		value := bits % int32(bound)
		if int32(uint32(bits-value)+uint32(bound-1)) >= 0 {
			return int(value), draws, nil
		}
	}
}

type javaRandom struct{ state uint64 }

const (
	javaMultiplier = uint64(0x5deece66d)
	javaAddend     = uint64(0xb)
	javaMask       = uint64(1<<48) - 1
)

func newJavaRandom(seed int64) *javaRandom {
	return &javaRandom{state: (uint64(seed) ^ javaMultiplier) & javaMask}
}

func (r *javaRandom) next(bits uint) int32 {
	r.state = (r.state*javaMultiplier + javaAddend) & javaMask
	return int32(r.state >> (48 - bits))
}

func (r *javaRandom) nextInt(bound int) (int, int, error) {
	if bound <= 0 {
		return 0, 0, errors.New("non-positive random bound")
	}
	if bound&(bound-1) == 0 {
		return int((int64(bound) * int64(r.next(31))) >> 31), 1, nil
	}
	draws := 0
	for {
		bits := r.next(31)
		draws++
		value := bits % int32(bound)
		if int32(uint32(bits-value)+uint32(bound-1)) >= 0 {
			return int(value), draws, nil
		}
	}
}

func randomSource(options Options) (boundedRandom, error) {
	if options.Random != nil && options.Seed != nil {
		return nil, errors.New("hookresolve: Random and Seed are mutually exclusive")
	}
	if options.Seed != nil {
		return newJavaRandom(*options.Seed), nil
	}
	reader := options.Random
	if reader == nil {
		reader = cryptorand.Reader
	}
	return readerRandom{reader: reader}, nil
}

func shuffle[T any](values []T, random boundedRandom) (int, error) {
	draws := 0
	for size := len(values); size > 1; size-- {
		index, consumed, err := random.nextInt(size)
		draws += consumed
		if err != nil {
			return draws, err
		}
		values[size-1], values[index] = values[index], values[size-1]
	}
	return draws, nil
}
