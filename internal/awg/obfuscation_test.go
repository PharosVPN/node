// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package awg

import "testing"

// TestGenerateObfuscationConstraints exercises the generator enough times to
// catch a constraint that only fails for some random draws.
func TestGenerateObfuscationConstraints(t *testing.T) {
	for i := 0; i < 500; i++ {
		o, err := generateObfuscation()
		if err != nil {
			t.Fatalf("generateObfuscation: %v", err)
		}
		if err := o.Validate(); err != nil {
			t.Fatalf("generated set fails Validate: %v (%+v)", err, o)
		}
		if o.Jc < jcMin || o.Jc > jcMax {
			t.Errorf("Jc = %d, want [%d,%d]", o.Jc, jcMin, jcMax)
		}
		for _, s := range []struct {
			name string
			val  uint32
		}{{"S1", o.S1}, {"S2", o.S2}, {"S3", o.S3}, {"S4", o.S4}} {
			if s.val < sLo || s.val > sHi {
				t.Errorf("%s = %d, want [%d,%d]", s.name, s.val, sLo, sHi)
			}
		}
	}
}

// TestObfuscationIsPerNodeRandom checks two generated sets differ — each node
// must randomise its own obfuscation, not share a fleet-wide set.
func TestObfuscationIsPerNodeRandom(t *testing.T) {
	a, err := generateObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two generated obfuscation sets are identical — not per-node random")
	}
}

func TestObfuscationValidate(t *testing.T) {
	good, err := generateObfuscation()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		mutate  func(o *Obfuscation)
		wantErr bool
	}{
		{"valid", func(*Obfuscation) {}, false},
		{"jmin>jmax", func(o *Obfuscation) { o.Jmin = o.Jmax + 1 }, true},
		{"jmin==jmax allowed", func(o *Obfuscation) { o.Jmin = o.Jmax }, false},
		{"header below min", func(o *Obfuscation) { o.H1 = 4 }, true},
		{"headers not distinct", func(o *Obfuscation) { o.H2 = o.H1 }, true},
		{"s2 collides with s1", func(o *Obfuscation) { o.S2 = o.S1 + s2HeaderOffset }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := good
			tc.mutate(&o)
			err := o.Validate()
			if tc.wantErr && err == nil {
				t.Error("Validate = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate = %v, want nil", err)
			}
		})
	}
}
