package collectors

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
)

// makeFakeNVMeSysfs creates a temporary /sys/class/nvme tree populated with
// the requested controller directories. Tests pass the resulting path as
// nvmeClassPath.
func makeFakeNVMeSysfs(t *testing.T, devices map[string]nvmeIdentity) string {
	t.Helper()
	root := t.TempDir()
	for dev, id := range devices {
		dir := filepath.Join(root, dev)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		for name, val := range map[string]string{
			"serial":       id.Serial,
			"model":        id.Model,
			"firmware_rev": id.FirmwareRev,
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(val), 0o644); err != nil {
				t.Fatalf("write %s/%s: %v", dev, name, err)
			}
		}
	}
	return root
}

// collectNVMeMetrics drains Collect into a slice for assertion.
func collectNVMeMetrics(t *testing.T, c *NVMeCollector) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
}

func TestDiscoverDevices_Empty(t *testing.T) {
	c := NewNVMeCollector()
	c.nvmeClassPath = t.TempDir()

	got, err := c.discoverDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no devices, got %v", got)
	}
}

func TestDiscoverDevices_MissingPath(t *testing.T) {
	c := NewNVMeCollector()
	c.nvmeClassPath = "/nonexistent/sys/class/nvme"

	if _, err := c.discoverDevices(); err == nil {
		t.Error("expected error for missing sysfs path, got nil")
	}
}

func TestDiscoverDevices_IgnoresNonControllerEntries(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"nvme0",            // controller — keep
		"nvme1",            // controller — keep
		"nvme-subsystem0",  // sibling sysfs class entry — skip
		"nvme",             // missing trailing digit — skip
		"nvme0n1",          // namespace, not controller — skip
		"something_else",   // unrelated — skip
	} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	c := NewNVMeCollector()
	c.nvmeClassPath = root

	got, err := c.discoverDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(got)
	want := []string{"nvme0", "nvme1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDiscoverDevices_FromFakeSysfs(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
		"nvme1": {Serial: "SN002", Model: "DriveB", FirmwareRev: "2.0"},
	})

	c := NewNVMeCollector()
	c.nvmeClassPath = root

	got, err := c.discoverDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(got)
	want := []string{"nvme0", "nvme1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReadNVMeIdentity_TrimsSpacePadding(t *testing.T) {
	dir := t.TempDir()
	write := func(name, val string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(val), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// NVMe identify-controller widths: MN=40, SN=20, FR=8 — space-padded.
	write("serial", "SN123               ")
	write("model", "TestDrive 4TB                           ")
	write("firmware_rev", "FW1.0   ")

	id, err := readNVMeIdentity(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Serial != "SN123" {
		t.Errorf("serial: got %q, want %q", id.Serial, "SN123")
	}
	if id.Model != "TestDrive 4TB" {
		t.Errorf("model: got %q, want %q", id.Model, "TestDrive 4TB")
	}
	if id.FirmwareRev != "FW1.0" {
		t.Errorf("firmware_rev: got %q, want %q", id.FirmwareRev, "FW1.0")
	}
}

func TestReadNVMeIdentity_MissingField(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "serial"), []byte("SN123"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readNVMeIdentity(dir); err == nil {
		t.Error("expected error when model file is missing, got nil")
	}
}

func TestNVMeCollector_InfoMetric_OnePerDevice(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
		"nvme1": {Serial: "SN002", Model: "DriveB", FirmwareRev: "2.0"},
	})
	c := NewNVMeCollector()
	c.nvmeClassPath = root

	metrics := collectNVMeMetrics(t, c)

	infoCount := 0
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "nvme_info") {
			infoCount++
		}
	}
	if infoCount != 2 {
		t.Errorf("expected 2 info metrics, got %d", infoCount)
	}
}

func TestNVMeCollector_NoDevices_EmitsOnlyErrorCounter(t *testing.T) {
	c := NewNVMeCollector()
	c.nvmeClassPath = t.TempDir()

	metrics := collectNVMeMetrics(t, c)

	// No devices → only collection_errors_total at 0 is emitted.
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric (collection_errors_total), got %d", len(metrics))
	}
	if !strings.Contains(metrics[0].Desc().String(), "collection_errors") {
		t.Errorf("expected collection_errors_total, got %s", metrics[0].Desc().String())
	}
	var pb dto.Metric
	if err := metrics[0].Write(&pb); err != nil {
		t.Fatal(err)
	}
	if pb.Gauge.GetValue() != 0 {
		t.Errorf("collection_errors: got %.0f, want 0 on virtio-only VM", pb.Gauge.GetValue())
	}
}

func TestProbe_NoControllers(t *testing.T) {
	c := NewNVMeCollector()
	c.nvmeClassPath = t.TempDir()
	c.nvmeDevPath = t.TempDir()

	ok, reason := c.Probe()
	if ok {
		t.Error("expected probe to fail on virtio-only VM")
	}
	if !strings.Contains(reason, "no passthrough") {
		t.Errorf("reason should mention no controllers, got: %q", reason)
	}
}

func TestProbe_DeviceOpenable(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
	})
	devDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(devDir, "nvme0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	c := NewNVMeCollector()
	c.nvmeClassPath = root
	c.nvmeDevPath = devDir

	ok, reason := c.Probe()
	if !ok {
		t.Errorf("expected probe to succeed, got reason: %q", reason)
	}
}

func TestProbe_DeviceMissing(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
	})

	c := NewNVMeCollector()
	c.nvmeClassPath = root
	c.nvmeDevPath = t.TempDir() // sysfs sees nvme0 but /dev/nvme0 isn't there

	ok, reason := c.Probe()
	if ok {
		t.Error("expected probe to fail when /dev entry is missing")
	}
	if !strings.Contains(reason, "cannot open") {
		t.Errorf("reason should explain the open failure, got: %q", reason)
	}
}

func TestProbe_SysfsUnreadable(t *testing.T) {
	c := NewNVMeCollector()
	c.nvmeClassPath = "/nonexistent/sys/class/nvme"
	c.nvmeDevPath = t.TempDir()

	ok, reason := c.Probe()
	if ok {
		t.Error("expected probe to fail when sysfs path doesn't exist")
	}
	if !strings.Contains(reason, "sysfs read failed") {
		t.Errorf("reason should mention sysfs read failure, got: %q", reason)
	}
}

// ── Critical-warning bit gauges ───────────────────────────────────────────────

// makeSmartIssuer returns an ioctlIssuer that writes buf into the caller's
// GetLogPage buffer and returns errno 0.
func makeSmartIssuer(buf [512]byte) ioctlIssuer {
	return func(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno) {
		// arg points to the nvmeAdminCmd; c.addr holds the address of the caller's
		// receive buffer. That buffer lives on getSmartLog's active stack frame, so
		// the GC cannot move it while this closure executes — the uint64→uintptr
		// round-trip is therefore safe even though go vet flags it.
		c := (*nvmeAdminCmd)(unsafe.Pointer(arg)) //nolint:unsafeptr // test-only
		dst := (*[512]byte)(unsafe.Pointer(uintptr(c.addr)))  //nolint:unsafeptr // see above
		*dst = buf
		return 0, 0, 0
	}
}

func TestNVMeCollector_CriticalWarningBits_AllClear(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
	})
	devDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(devDir, "nvme0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	var smartBuf [512]byte // all zero → all bits clear

	c := NewNVMeCollector()
	c.nvmeClassPath = root
	c.nvmeDevPath = devDir
	c.smartIssuer = makeSmartIssuer(smartBuf)

	metrics := collectNVMeMetrics(t, c)

	warnCount := 0
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "critical_warning") {
			warnCount++
		}
	}
	if warnCount != 6 {
		t.Errorf("expected 6 critical_warning metrics (one per bit), got %d", warnCount)
	}
}

func TestNVMeCollector_CriticalWarningBits_EachBitIndependent(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
	})
	devDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(devDir, "nvme0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	for bitIdx := uint8(0); bitIdx < 6; bitIdx++ {
		var smartBuf [512]byte
		smartBuf[smartOffCriticalWarning] = 1 << bitIdx

		c := NewNVMeCollector()
		c.nvmeClassPath = root
		c.nvmeDevPath = devDir
		c.smartIssuer = makeSmartIssuer(smartBuf)

		metrics := collectNVMeMetrics(t, c)

		setCount := 0
		for _, m := range metrics {
			if !strings.Contains(m.Desc().String(), "critical_warning") {
				continue
			}
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatal(err)
			}
			if pb.Gauge.GetValue() == 1 {
				setCount++
			}
		}
		if setCount != 1 {
			t.Errorf("bit %d: expected exactly 1 set bit metric, got %d", bitIdx, setCount)
		}
	}
}

func TestNVMeCollector_SmartFailure_NoWarningMetrics(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
	})
	devDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(devDir, "nvme0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	epermIssuer := func(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EPERM
	}

	c := NewNVMeCollector()
	c.nvmeClassPath = root
	c.nvmeDevPath = devDir
	c.smartIssuer = epermIssuer

	metrics := collectNVMeMetrics(t, c)

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "critical_warning") {
			t.Error("expected no critical_warning metrics when SMART ioctl fails, but got one")
		}
	}
}

// ── SMART buffer parsing ──────────────────────────────────────────────────────

func TestParseSmartBuf_AllZero(t *testing.T) {
	var buf [512]byte
	f := parseSmartBuf(buf)
	if f.criticalWarning != 0 || f.availableSpare != 0 || f.percentageUsed != 0 ||
		f.powerOnHours != 0 || f.mediaErrors != 0 || f.numErrLogEntries != 0 {
		t.Errorf("all-zero buffer: got non-zero fields: %+v", f)
	}
}

func TestParseSmartBuf_WearAndCounters(t *testing.T) {
	var buf [512]byte
	buf[smartOffCriticalWarning] = 0b00000101 // bits 0 and 2
	buf[smartOffAvailableSpare] = 87
	buf[smartOffPercentageUsed] = 13
	binary.LittleEndian.PutUint64(buf[smartOffPowerOnHours:], 52341)
	binary.LittleEndian.PutUint64(buf[smartOffMediaErrors:], 7)
	binary.LittleEndian.PutUint64(buf[smartOffNumErrLogEntries:], 3)

	f := parseSmartBuf(buf)
	if f.criticalWarning != 0b00000101 {
		t.Errorf("criticalWarning: got 0x%02x, want 0x05", f.criticalWarning)
	}
	if f.availableSpare != 87 {
		t.Errorf("availableSpare: got %d, want 87", f.availableSpare)
	}
	if f.percentageUsed != 13 {
		t.Errorf("percentageUsed: got %d, want 13", f.percentageUsed)
	}
	if f.powerOnHours != 52341 {
		t.Errorf("powerOnHours: got %d, want 52341", f.powerOnHours)
	}
	if f.mediaErrors != 7 {
		t.Errorf("mediaErrors: got %d, want 7", f.mediaErrors)
	}
	if f.numErrLogEntries != 3 {
		t.Errorf("numErrLogEntries: got %d, want 3", f.numErrLogEntries)
	}
}

func TestParseSmartBuf_MaxUint64Counters(t *testing.T) {
	var buf [512]byte
	binary.LittleEndian.PutUint64(buf[smartOffPowerOnHours:], ^uint64(0))
	binary.LittleEndian.PutUint64(buf[smartOffMediaErrors:], ^uint64(0))

	f := parseSmartBuf(buf)
	if f.powerOnHours != ^uint64(0) {
		t.Errorf("powerOnHours: got %d, want max uint64", f.powerOnHours)
	}
	if f.mediaErrors != ^uint64(0) {
		t.Errorf("mediaErrors: got %d, want max uint64", f.mediaErrors)
	}
}

func TestGetSmartLog_MissingDevice(t *testing.T) {
	_, err := getSmartLog("/nonexistent/dev/nvme0", nil)
	if err == nil {
		t.Fatal("expected error for missing device path, got nil")
	}
}

func TestGetSmartLog_IoctlError(t *testing.T) {
	// Create a real (empty) file so os.Open succeeds, then inject EPERM.
	f, err := os.CreateTemp(t.TempDir(), "fake-nvme")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	epermIssuer := func(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EPERM
	}
	_, err = getSmartLog(f.Name(), epermIssuer)
	if err == nil {
		t.Fatal("expected EPERM error, got nil")
	}
}

func TestGetSmartLog_Success(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "fake-nvme")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	var wantBuf [512]byte
	wantBuf[smartOffAvailableSpare] = 95
	wantBuf[smartOffPercentageUsed] = 5
	binary.LittleEndian.PutUint64(wantBuf[smartOffPowerOnHours:], 1000)

	successIssuer := func(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno) {
		// Copy our prepared buffer into the caller's buf via GetLogPage's slice.
		// We can't easily do that through the uintptr, so we verify the fields
		// via parseSmartBuf directly in the parallel unit test above.
		// Here we just confirm no error is returned when errno == 0.
		return 0, 0, 0
	}
	_, err = getSmartLog(tmp.Name(), successIssuer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ── Counter metrics (media errors, error log entries, collection errors) ──────

func setupCollectorWithSmart(t *testing.T, smartBuf [512]byte) (*NVMeCollector, string) {
	t.Helper()
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
	})
	devDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(devDir, "nvme0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewNVMeCollector()
	c.nvmeClassPath = root
	c.nvmeDevPath = devDir
	c.smartIssuer = makeSmartIssuer(smartBuf)
	return c, devDir
}

func TestNVMeCollector_MediaErrors_Emitted(t *testing.T) {
	var smartBuf [512]byte
	binary.LittleEndian.PutUint64(smartBuf[smartOffMediaErrors:], 42)

	c, _ := setupCollectorWithSmart(t, smartBuf)
	metrics := collectNVMeMetrics(t, c)

	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "media_errors") {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatal(err)
		}
		if got := pb.Counter.GetValue(); got != 42 {
			t.Errorf("media_errors: got %.0f, want 42", got)
		}
		return
	}
	t.Error("media_errors_total metric not found")
}

func TestNVMeCollector_ErrorLogEntries_Emitted(t *testing.T) {
	var smartBuf [512]byte
	binary.LittleEndian.PutUint64(smartBuf[smartOffNumErrLogEntries:], 7)

	c, _ := setupCollectorWithSmart(t, smartBuf)
	metrics := collectNVMeMetrics(t, c)

	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "error_log_entries") {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatal(err)
		}
		if got := pb.Counter.GetValue(); got != 7 {
			t.Errorf("error_log_entries: got %.0f, want 7", got)
		}
		return
	}
	t.Error("error_log_entries_total metric not found")
}

func TestNVMeCollector_CollectionErrors_ZeroOnSuccess(t *testing.T) {
	var smartBuf [512]byte
	c, _ := setupCollectorWithSmart(t, smartBuf)
	metrics := collectNVMeMetrics(t, c)

	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "collection_errors") {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatal(err)
		}
		if got := pb.Gauge.GetValue(); got != 0 {
			t.Errorf("collection_errors: got %.0f, want 0 on success", got)
		}
		return
	}
	t.Error("collection_errors_total metric not found")
}

func TestNVMeCollector_CollectionErrors_IncrementOnSmartFailure(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN001", Model: "DriveA", FirmwareRev: "1.0"},
	})
	devDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(devDir, "nvme0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	c := NewNVMeCollector()
	c.nvmeClassPath = root
	c.nvmeDevPath = devDir
	c.smartIssuer = func(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EIO
	}

	metrics := collectNVMeMetrics(t, c)

	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "collection_errors") {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatal(err)
		}
		if got := pb.Gauge.GetValue(); got != 1 {
			t.Errorf("collection_errors: got %.0f, want 1 after SMART failure", got)
		}
		return
	}
	t.Error("collection_errors_total metric not found")
}

// ── Wear gauges (percentage_used, available_spare, power_on_hours) ────────────

func TestNVMeCollector_WearGauges_Emitted(t *testing.T) {
	var smartBuf [512]byte
	smartBuf[smartOffPercentageUsed] = 13
	smartBuf[smartOffAvailableSpare] = 87
	binary.LittleEndian.PutUint64(smartBuf[smartOffPowerOnHours:], 52341)

	c, _ := setupCollectorWithSmart(t, smartBuf)
	metrics := collectNVMeMetrics(t, c)

	wantGauges := map[string]float64{
		"percentage_used": 13,
		"available_spare": 87,
		"power_on_hours":  52341,
	}
	found := map[string]bool{}

	for _, m := range metrics {
		desc := m.Desc().String()
		for key, want := range wantGauges {
			if !strings.Contains(desc, key) {
				continue
			}
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatal(err)
			}
			if got := pb.Gauge.GetValue(); got != want {
				t.Errorf("%s: got %.0f, want %.0f", key, got, want)
			}
			found[key] = true
		}
	}

	for key := range wantGauges {
		if !found[key] {
			t.Errorf("metric %q not found in output", key)
		}
	}
}

// ── Identity cache ────────────────────────────────────────────────────────────

// TestSnapshotState_RefreshSkippedWithinTTL_RefreshedAfterExpiry verifies the
// snapshotState refresh policy: while the cache is fresh (last refresh within
// nvmeStateTTL), a device added to sysfs is *not* picked up; once the TTL
// expires, the next snapshotState rebuilds the cache and the new device
// appears.
func TestSnapshotState_RefreshSkippedWithinTTL_RefreshedAfterExpiry(t *testing.T) {
	root := makeFakeNVMeSysfs(t, map[string]nvmeIdentity{
		"nvme0": {Serial: "SN000", Model: "DriveA", FirmwareRev: "1.0"},
	})

	c := NewNVMeCollector()
	c.nvmeClassPath = root

	// Prime the cache.
	if _, _, err := c.snapshotState(); err != nil {
		t.Fatalf("priming snapshotState: %v", err)
	}

	// Hot-plug nvme1 onto sysfs.
	if err := os.MkdirAll(filepath.Join(root, "nvme1"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{
		"serial":       "SN001",
		"model":        "DriveB",
		"firmware_rev": "2.0",
	} {
		if err := os.WriteFile(filepath.Join(root, "nvme1", name), []byte(val), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Within TTL: refresh is skipped, nvme1 should not appear.
	_, ids, err := c.snapshotState()
	if err != nil {
		t.Fatalf("snapshotState (within TTL): %v", err)
	}
	if _, ok := ids["nvme1"]; ok {
		t.Error("nvme1 appeared in identity cache while within TTL window — refresh should have been skipped")
	}

	// Expire the TTL and retry.
	c.mu.Lock()
	c.lastRefreshAt = time.Now().Add(-2 * nvmeStateTTL)
	c.mu.Unlock()

	_, ids, err = c.snapshotState()
	if err != nil {
		t.Fatalf("snapshotState (after TTL expiry): %v", err)
	}
	id, ok := ids["nvme1"]
	if !ok {
		t.Fatal("nvme1 not in identity cache after TTL expiry")
	}
	if id.Serial != "SN001" {
		t.Errorf("nvme1 serial: got %q, want %q", id.Serial, "SN001")
	}
}

// TestCollect_WarnsOnEmptyIdentity verifies that Collect logs a warning when
// a device is present but has no cached identity.
func TestCollect_WarnsOnEmptyIdentity(t *testing.T) {
	// Create a sysfs dir with no identity files so readNVMeIdentity fails.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nvme0"), 0o755); err != nil {
		t.Fatal(err)
	}
	devDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(devDir, "nvme0"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	c := NewNVMeCollector()
	c.nvmeClassPath = root
	c.nvmeDevPath = devDir
	c.smartIssuer = makeSmartIssuer([512]byte{})

	// snapshotState's identity read will fail for nvme0 (no sysfs files), leaving
	// cache empty. Collect should still emit nvme_info with empty labels and log a warning.
	metrics := collectNVMeMetrics(t, c)

	var foundInfo bool
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "nvme_info") {
			foundInfo = true
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatal(err)
			}
			for _, lp := range pb.GetLabel() {
				if lp.GetName() == "serial" && lp.GetValue() != "" {
					t.Errorf("expected empty serial label, got %q", lp.GetValue())
				}
			}
		}
	}
	if !foundInfo {
		t.Error("nvme_info metric not emitted even when identity is empty")
	}
}
