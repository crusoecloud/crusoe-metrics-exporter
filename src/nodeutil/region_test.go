package nodeutil

import (
	"testing"
)

func TestRegionFromNodeName(t *testing.T) {
	tests := []struct {
		name     string
		nodeName string
		want     string
		wantErr  bool
	}{
		{
			name:     "standard crusoe node name",
			nodeName: "np-88fe80e2-1.us-west1-a.compute.internal",
			want:     "us-west1-a",
		},
		{
			name:     "eu iceland region",
			nodeName: "np-abcd1234-0.eu-iceland1-a.compute.internal",
			want:     "eu-iceland1-a",
		},
		{
			name:     "eu norway region",
			nodeName: "np-deadbeef-3.eu-norway1-b.compute.internal",
			want:     "eu-norway1-b",
		},
		{
			name:     "us east region",
			nodeName: "np-12345678-2.us-east1-a.compute.internal",
			want:     "us-east1-a",
		},
		{
			name:     "empty node name",
			nodeName: "",
			wantErr:  true,
		},
		{
			name:     "no dots in node name",
			nodeName: "just-a-hostname",
			wantErr:  true,
		},
		{
			name:     "single dot with empty region",
			nodeName: "prefix.",
			wantErr:  true,
		},
		{
			name:     "minimal valid format",
			nodeName: "node.us-west1-a",
			want:     "us-west1-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RegionFromNodeName(tt.nodeName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("RegionFromNodeName(%q) expected error, got %q", tt.nodeName, got)
				}
				return
			}
			if err != nil {
				t.Errorf("RegionFromNodeName(%q) unexpected error: %v", tt.nodeName, err)
				return
			}
			if got != tt.want {
				t.Errorf("RegionFromNodeName(%q) = %q, want %q", tt.nodeName, got, tt.want)
			}
		})
	}
}

func TestObjStoreEndpoint(t *testing.T) {
	tests := []struct {
		region string
		want   string
	}{
		{"us-west1-a", "object.us-west1-a.crusoecloudcompute.com"},
		{"eu-iceland1-a", "object.eu-iceland1-a.crusoecloudcompute.com"},
		{"eu-norway1-b", "object.eu-norway1-b.crusoecloudcompute.com"},
	}

	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			got := ObjStoreEndpoint(tt.region)
			if got != tt.want {
				t.Errorf("ObjStoreEndpoint(%q) = %q, want %q", tt.region, got, tt.want)
			}
		})
	}
}
