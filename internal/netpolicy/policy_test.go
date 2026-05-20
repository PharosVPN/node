// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy

import "testing"

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		p       Policy
		wantErr bool
	}{
		{"all off", Policy{}, false},
		{"forwarding only", Policy{Forwarding: true}, false},
		{"forwarding + masquerade", Policy{Forwarding: true, Masquerade: true}, false},
		{"forwarding + isolation", Policy{Forwarding: true, Isolation: true}, false},
		{"all on", Policy{Forwarding: true, Masquerade: true, Isolation: true}, false},
		{"masquerade without forwarding", Policy{Masquerade: true}, true},
		{"isolation without forwarding", Policy{Isolation: true}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if tc.wantErr && err == nil {
				t.Error("Validate = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate = %v, want nil", err)
			}
		})
	}
}
