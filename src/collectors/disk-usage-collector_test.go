package collectors

import (
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// writeTempMountsFile creates a temporary mounts file with the given content
// and returns its path. The caller is responsible for removing it.
func writeTempMountsFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "mounts-*")
	if err != nil {
		t.Fatalf("Failed to create temp mounts file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp mounts file: %v", err)
	}
	f.Close()
	return f.Name()
}

// collectDiskUsageMetrics runs the collector and returns all emitted metrics.
func collectDiskUsageMetrics(t *testing.T, c *DiskUsageCollector) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)
	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}
	return metrics
}

// descString returns the string representation of a metric's descriptor.
func descString(m prometheus.Metric) string {
	return m.Desc().String()
}

// TestDiskUsageCollector_SkipsNonVdDevices verifies that non-vd devices
// (overlay, tmpfs, nfs, sda) are ignored and only vd* partitions are attempted.
func TestDiskUsageCollector_SkipsNonVdDevices(t *testing.T) {
	mounts := `overlay / overlay rw,relatime 0 0
tmpfs /tmp tmpfs rw,relatime 0 0
/dev/sda1 /other ext4 rw,relatime 0 0
100.64.0.2:/volumes/abc /mnt/nfs nfs rw,relatime 0 0
`
	mountsPath := writeTempMountsFile(t, mounts)
	defer os.Remove(mountsPath)

	c := NewDiskUsageCollector(mountsPath, "")
	metrics := collectDiskUsageMetrics(t, c)

	// None of the above match vd* so we should get only the error counter metric.
	if len(metrics) != 1 {
		t.Errorf("Expected only the error counter metric (1), got %d metrics", len(metrics))
	}
	if !strings.Contains(descString(metrics[0]), "errors") {
		t.Errorf("Expected error counter metric, got: %s", descString(metrics[0]))
	}
}

// TestDiskUsageCollector_DeduplicatesDevices verifies that if the same device
// appears twice in the mounts file (bind mount), it is only reported once.
func TestDiskUsageCollector_DeduplicatesDevices(t *testing.T) {
	// Both entries are /tmp which statfs can resolve, but vda1 should only
	// appear once due to the seen map.
	mounts := `/dev/vda1 /tmp ext4 rw,relatime 0 0
/dev/vda1 /tmp ext4 rw,relatime 0 0
`
	mountsPath := writeTempMountsFile(t, mounts)
	defer os.Remove(mountsPath)

	c := NewDiskUsageCollector(mountsPath, "")
	metrics := collectDiskUsageMetrics(t, c)

	// Should be exactly 3: bytes_used, inodes_used, collection_errors
	if len(metrics) != 3 {
		t.Errorf("Expected 3 metrics (bytes_used + inodes_used + errors), got %d", len(metrics))
	}
}

// TestDiskUsageCollector_StatfsOnRealPath verifies that statfs works correctly
// when pointed at a real local path, returning non-zero filesystem stats.
func TestDiskUsageCollector_StatfsOnRealPath(t *testing.T) {
	// Use /tmp as the mount point — it always exists and statfs will succeed.
	mounts := `/dev/vda1 /tmp ext4 rw,relatime 0 0
`
	mountsPath := writeTempMountsFile(t, mounts)
	defer os.Remove(mountsPath)

	c := NewDiskUsageCollector(mountsPath, "")
	metrics := collectDiskUsageMetrics(t, c)

	// Expect exactly 3 metrics: bytes_used, inodes_used, collection_errors
	if len(metrics) != 3 {
		t.Errorf("Expected 3 metrics, got %d", len(metrics))
	}

	// Verify we got a bytes_used and inodes_used metric
	foundBytes := false
	foundInodes := false
	for _, m := range metrics {
		desc := descString(m)
		if strings.Contains(desc, "bytes_used") {
			foundBytes = true
		}
		if strings.Contains(desc, "inodes_used") {
			foundInodes = true
		}
	}
	if !foundBytes {
		t.Error("Expected crusoe_vm_disk_bytes_used metric but did not find it")
	}
	if !foundInodes {
		t.Error("Expected crusoe_vm_disk_inodes_used metric but did not find it")
	}
}

// TestDiskUsageCollector_MissingMountsFile verifies that when the mounts file
// cannot be opened, a single error metric is emitted and the collector does not panic.
func TestDiskUsageCollector_MissingMountsFile(t *testing.T) {
	c := NewDiskUsageCollector("/nonexistent/path/to/mounts", "")
	metrics := collectDiskUsageMetrics(t, c)

	if len(metrics) != 1 {
		t.Errorf("Expected exactly 1 error metric, got %d", len(metrics))
	}
	if !strings.Contains(descString(metrics[0]), "errors") {
		t.Errorf("Expected an error metric, got: %s", descString(metrics[0]))
	}
}

// TestDiskUsageCollector_Describe verifies that all 3 metric descriptors are emitted.
func TestDiskUsageCollector_Describe(t *testing.T) {
	c := NewDiskUsageCollector("/proc/1/mounts", "")
	ch := make(chan *prometheus.Desc, 10)
	c.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count != 3 {
		t.Errorf("Expected 3 descriptors, got %d", count)
	}
}
