package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// GLP1: only the bytes that differ from the original are stored.
// No byte of the original game file is present in this patch.
//
//	"GLP1"
//	u16 noteLen, note
//	u32 fileCount
//	per file:
//	  u16 targetLen, target
//	  [32]byte sha256 of the original
//	  [32]byte sha256 of the result
//	  u64 originalSize, u64 resultSize, u32 runCount
//	  per run: u64 offset, u32 length, length bytes

type Run struct {
	Off  uint64
	Data []byte
}

type Target struct {
	Path    string // relative to the GMod root, forward slashes
	OldHash [32]byte
	NewHash [32]byte
	OldSize uint64
	NewSize uint64
	Runs    []Run
}

type Patch struct {
	Note    string
	Targets []Target
}

type reader struct {
	d []byte
	p int
}

func (r *reader) need(n int) ([]byte, error) {
	if r.p+n > len(r.d) {
		return nil, errors.New("patch file is truncated")
	}
	b := r.d[r.p : r.p+n]
	r.p += n
	return b, nil
}

func (r *reader) u16() (uint16, error) {
	b, err := r.need(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *reader) u32() (uint32, error) {
	b, err := r.need(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *reader) u64() (uint64, error) {
	b, err := r.need(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func ParsePatch(d []byte) (*Patch, error) {
	r := &reader{d: d}
	magic, err := r.need(4)
	if err != nil || string(magic) != "GLP1" {
		return nil, errors.New("not a GLP1 patch")
	}
	nl, err := r.u16()
	if err != nil {
		return nil, err
	}
	note, err := r.need(int(nl))
	if err != nil {
		return nil, err
	}
	nf, err := r.u32()
	if err != nil {
		return nil, err
	}
	p := &Patch{Note: string(note)}
	for i := uint32(0); i < nf; i++ {
		tl, err := r.u16()
		if err != nil {
			return nil, err
		}
		tb, err := r.need(int(tl))
		if err != nil {
			return nil, err
		}
		t := Target{Path: string(tb)}
		h, err := r.need(32)
		if err != nil {
			return nil, err
		}
		copy(t.OldHash[:], h)
		h, err = r.need(32)
		if err != nil {
			return nil, err
		}
		copy(t.NewHash[:], h)
		if t.OldSize, err = r.u64(); err != nil {
			return nil, err
		}
		if t.NewSize, err = r.u64(); err != nil {
			return nil, err
		}
		nr, err := r.u32()
		if err != nil {
			return nil, err
		}
		for j := uint32(0); j < nr; j++ {
			off, err := r.u64()
			if err != nil {
				return nil, err
			}
			ln, err := r.u32()
			if err != nil {
				return nil, err
			}
			blob, err := r.need(int(ln))
			if err != nil {
				return nil, err
			}
			t.Runs = append(t.Runs, Run{Off: off, Data: blob})
		}
		p.Targets = append(p.Targets, t)
	}
	if r.p != len(r.d) {
		return nil, fmt.Errorf("patch has %d trailing bytes", len(r.d)-r.p)
	}
	return p, nil
}

// Apply builds the patched contents from the original bytes.
func (t *Target) Apply(orig []byte) ([]byte, error) {
	if uint64(len(orig)) != t.OldSize {
		return nil, fmt.Errorf("size is %d, expected %d", len(orig), t.OldSize)
	}
	if sha256.Sum256(orig) != t.OldHash {
		return nil, errors.New("hash does not match the supported build")
	}
	out := make([]byte, t.NewSize)
	n := t.OldSize
	if t.NewSize < n {
		n = t.NewSize // the file shrinks: the Authenticode signature is dropped
	}
	copy(out, orig[:n])
	for _, run := range t.Runs {
		if run.Off+uint64(len(run.Data)) > t.NewSize {
			return nil, errors.New("a run falls outside the file")
		}
		copy(out[run.Off:], run.Data)
	}
	if sha256.Sum256(out) != t.NewHash {
		return nil, errors.New("the result does not match the hash recorded in the patch")
	}
	return out, nil
}
