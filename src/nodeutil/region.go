// Package nodeutil provides helpers for extracting metadata from Crusoe node names.
package nodeutil

import (
	"fmt"
	"strings"
)

// RegionFromNodeName extracts the Crusoe region from a Kubernetes node name.
// Crusoe managed-k8s nodes follow the naming convention:
//
//	<pool>-<id>.<region>.compute.internal
//
// For example "np-88fe80e2-1.us-west1-a.compute.internal" → "us-west1-a".
// Returns an error if nodeName is empty or does not contain the expected format.
func RegionFromNodeName(nodeName string) (string, error) {
	if nodeName == "" {
		return "", fmt.Errorf("NODE_NAME is empty")
	}

	parts := strings.SplitN(nodeName, ".", 3)
	if len(parts) < 2 || parts[1] == "" {
		return "", fmt.Errorf("cannot extract region from node name %q: expected <prefix>.<region>.compute.internal", nodeName)
	}

	return parts[1], nil
}

// ObjStoreEndpoint returns the object-store FQDN for the given Crusoe region.
// Example: "us-west1-a" → "object.us-west1-a.crusoecloudcompute.com"
func ObjStoreEndpoint(region string) string {
	return fmt.Sprintf("object.%s.crusoecloudcompute.com", region)
}
