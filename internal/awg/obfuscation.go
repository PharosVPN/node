// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package awg manages a buoy node's AmneziaWG server identity: its WireGuard
// keypair and its per-node-random obfuscation parameter set.
//
// Each node randomises its own obfuscation set — never fleet-wide — for
// traffic diversity. The set is generated once, persisted, and reported to
// coxswain via GetStatus; coxswain caches it and hands the exact values to every
// client of the node, so caravel can build a tunnel that handshakes
// (DESIGN §3).
package awg

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"
)

// Obfuscation bounds. The ranges keep handshakes performant while still
// randomising every node distinctly.
const (
	jcMin, jcMax     = 3, 10    // junk packet count — kept small
	jMinLo, jMinHi   = 25, 75   // Jmin range
	jSpanLo, jSpanHi = 700, 900 // Jmax = Jmin + span
	sLo, sHi         = 15, 150  // S1-S4 junk sizes — bounded

	// hMin is the lowest legal magic header. Values 1-4 are reserved by
	// AmneziaWG for its standard packet types, so headers start at 5.
	hMin uint32 = 5
	// hMax keeps headers within the positive int32 range — comfortably random
	// while avoiding any signed-interpretation surprises across tools.
	hMax uint32 = 1<<31 - 1

	// s2HeaderOffset is the AmneziaWG init-packet header length. S2 must not
	// equal S1+s2HeaderOffset, or an init packet and a response packet become
	// indistinguishable and AmneziaWG rejects the config.
	s2HeaderOffset = 56
)

// Obfuscation is one node's AmneziaWG obfuscation parameter set. JSON tags
// match the persisted state file; the field order matches the AmneziaWG
// config keys.
type Obfuscation struct {
	Jc   uint32 `json:"jc"`
	Jmin uint32 `json:"jmin"`
	Jmax uint32 `json:"jmax"`
	S1   uint32 `json:"s1"`
	S2   uint32 `json:"s2"`
	S3   uint32 `json:"s3"`
	S4   uint32 `json:"s4"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
	// I1-I5 are special-junk packet templates. buoy leaves them empty; the
	// fields exist so a persisted set round-trips the full schema.
	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`
}

// generateObfuscation produces a fresh per-node-random obfuscation set that
// satisfies every constraint Validate enforces.
func generateObfuscation() (Obfuscation, error) {
	o := Obfuscation{}
	var err error

	if o.Jc, err = randRange(jcMin, jcMax); err != nil {
		return Obfuscation{}, err
	}
	if o.Jmin, err = randRange(jMinLo, jMinHi); err != nil {
		return Obfuscation{}, err
	}
	span, err := randRange(jSpanLo, jSpanHi)
	if err != nil {
		return Obfuscation{}, err
	}
	o.Jmax = o.Jmin + span

	for _, p := range []*uint32{&o.S1, &o.S2, &o.S3, &o.S4} {
		if *p, err = randRange(sLo, sHi); err != nil {
			return Obfuscation{}, err
		}
	}
	// Keep an init packet distinguishable from a response packet.
	for o.S2 == o.S1+s2HeaderOffset {
		if o.S2, err = randRange(sLo, sHi); err != nil {
			return Obfuscation{}, err
		}
	}

	headers, err := distinctHeaders()
	if err != nil {
		return Obfuscation{}, err
	}
	o.H1, o.H2, o.H3, o.H4 = headers[0], headers[1], headers[2], headers[3]

	return o, nil
}

// distinctHeaders returns four distinct magic headers, each >= hMin.
func distinctHeaders() ([4]uint32, error) {
	var hs [4]uint32
	seen := make(map[uint32]bool, 4)
	for i := 0; i < 4; {
		h, err := randRange(hMin, hMax)
		if err != nil {
			return hs, err
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		hs[i] = h
		i++
	}
	return hs, nil
}

// Validate checks the structural rules the control.proto AmneziaWGObfuscation
// contract requires every generator and validator to enforce: jmin <= jmax,
// h1-h4 distinct and >= 5, and s2 != s1+56. It guards a persisted set loaded
// from disk against corruption. (generateObfuscation produces jmin strictly
// below jmax; the contract permits equality.)
func (o Obfuscation) Validate() error {
	if o.Jmin > o.Jmax {
		return fmt.Errorf("awg: Jmin (%d) must be <= Jmax (%d)", o.Jmin, o.Jmax)
	}
	hs := [4]uint32{o.H1, o.H2, o.H3, o.H4}
	seen := make(map[uint32]bool, 4)
	for i, h := range hs {
		if h < hMin {
			return fmt.Errorf("awg: H%d (%d) must be >= %d", i+1, h, hMin)
		}
		if seen[h] {
			return fmt.Errorf("awg: magic headers H1-H4 must be distinct (%d repeats)", h)
		}
		seen[h] = true
	}
	if o.S2 == o.S1+s2HeaderOffset {
		return fmt.Errorf("awg: S2 (%d) must not equal S1+%d", o.S2, s2HeaderOffset)
	}
	return nil
}

// toProto converts the set to its wire form.
func (o Obfuscation) toProto() *buoyv1.AmneziaWGObfuscation {
	return &buoyv1.AmneziaWGObfuscation{
		Jc: o.Jc, Jmin: o.Jmin, Jmax: o.Jmax,
		S1: o.S1, S2: o.S2, S3: o.S3, S4: o.S4,
		H1: o.H1, H2: o.H2, H3: o.H3, H4: o.H4,
		I1: o.I1, I2: o.I2, I3: o.I3, I4: o.I4, I5: o.I5,
	}
}

// ObfuscationFromProto converts a wire obfuscation set to the local form. Used
// for a cascade inner link, whose [Interface] adopts the exit node's set so the
// handshake to the exit matches (DESIGN §3).
func ObfuscationFromProto(p *buoyv1.AmneziaWGObfuscation) Obfuscation {
	if p == nil {
		return Obfuscation{}
	}
	return Obfuscation{
		Jc: p.GetJc(), Jmin: p.GetJmin(), Jmax: p.GetJmax(),
		S1: p.GetS1(), S2: p.GetS2(), S3: p.GetS3(), S4: p.GetS4(),
		H1: p.GetH1(), H2: p.GetH2(), H3: p.GetH3(), H4: p.GetH4(),
		I1: p.GetI1(), I2: p.GetI2(), I3: p.GetI3(), I4: p.GetI4(), I5: p.GetI5(),
	}
}

// Render renders the obfuscation parameters as the lines buoy writes into the
// [Interface] section of a conf. The data-plane writer applies the conf so the
// served config matches exactly what GetStatus reports.
func (o Obfuscation) Render() string {
	var b strings.Builder
	for _, kv := range []struct {
		key string
		val uint32
	}{
		{"Jc", o.Jc}, {"Jmin", o.Jmin}, {"Jmax", o.Jmax},
		{"S1", o.S1}, {"S2", o.S2}, {"S3", o.S3}, {"S4", o.S4},
		{"H1", o.H1}, {"H2", o.H2}, {"H3", o.H3}, {"H4", o.H4},
	} {
		fmt.Fprintf(&b, "%s = %d\n", kv.key, kv.val)
	}
	for i, tmpl := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
		if tmpl != "" {
			fmt.Fprintf(&b, "I%d = %s\n", i+1, tmpl)
		}
	}
	return b.String()
}

// randRange returns a uniform random uint32 in the inclusive range [lo, hi].
func randRange(lo, hi uint32) (uint32, error) {
	if lo > hi {
		return 0, fmt.Errorf("awg: invalid range [%d,%d]", lo, hi)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)+1))
	if err != nil {
		return 0, fmt.Errorf("awg: random: %w", err)
	}
	return lo + uint32(n.Int64()), nil
}
