package collectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeSysClassBlock builds a /sys/class/block look-alike: every entry is a
// symlink to a device directory holding a "dev" file, as in real sysfs.
func fakeSysClassBlock(t *testing.T, devs map[string]string) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "class", "block")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, dev := range devs {
		target := filepath.Join(base, "devices", name)
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "dev"), []byte(dev+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// useFakeSysClassBlock points the collector at root and empties the cache for one test.
func useFakeSysClassBlock(t *testing.T, root string) {
	t.Helper()
	oldPath := sysClassBlockPath
	deviceMutex.Lock()
	oldCache := deviceCache
	deviceCache = make(map[uint32]string)
	deviceMutex.Unlock()
	sysClassBlockPath = root
	t.Cleanup(func() {
		sysClassBlockPath = oldPath
		deviceMutex.Lock()
		deviceCache = oldCache
		deviceMutex.Unlock()
	})
}

// TestScanVirtioDevicesFollowsSymlinksAndIncludesPartitions: sysfs entries are
// symlinks, and requests carry partition device numbers (vda1 = 252:1).
func TestScanVirtioDevicesFollowsSymlinksAndIncludesPartitions(t *testing.T) {
	root := fakeSysClassBlock(t, map[string]string{
		"vda": "252:0", "vda1": "252:1", "vda15": "252:15", "vdb": "252:16", "nvme0n1": "259:0",
	})
	got, err := scanVirtioDevices(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32]string{252<<8 | 0: "vda", 252<<8 | 1: "vda1", 252<<8 | 15: "vda15", 252<<8 | 16: "vdb"}
	if len(got) != len(want) {
		t.Fatalf("expected %d virtio devices, got %v", len(want), got)
	}
	for id, name := range want {
		if got[id] != name {
			t.Errorf("device %d:%d: expected %s, got %q", id>>8, id&0xFF, name, got[id])
		}
	}
}

// TestInitDeviceCacheFindsPartitions: the boot disk's partition resolves to vda1, not vd253:1.
func TestInitDeviceCacheFindsPartitions(t *testing.T) {
	useFakeSysClassBlock(t, fakeSysClassBlock(t, map[string]string{"vda": "253:0", "vda1": "253:1"}))
	if err := initDeviceCache(); err != nil {
		t.Fatal(err)
	}
	if got := getDeviceName(253<<8 | 1); got != "vda1" {
		t.Errorf("expected vda1, got %s", got)
	}
}

// TestGetDeviceNameCacheMissDoesNotDeadlock: a miss that then finds the device
// must not hold the read lock while taking the write lock (RWMutex can't upgrade).
func TestGetDeviceNameCacheMissDoesNotDeadlock(t *testing.T) {
	useFakeSysClassBlock(t, fakeSysClassBlock(t, map[string]string{"vda1": "252:1"}))
	done := make(chan string, 1)
	go func() { done <- getDeviceName(252<<8 | 1) }()
	select {
	case got := <-done:
		if got != "vda1" {
			t.Errorf("expected vda1, got %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("getDeviceName deadlocked on a cache miss")
	}
}

// TestGetDeviceNameUnknownFallsBack keeps the old fallback format for unknown devices.
func TestGetDeviceNameUnknownFallsBack(t *testing.T) {
	useFakeSysClassBlock(t, fakeSysClassBlock(t, map[string]string{"vda": "252:0"}))
	if got := getDeviceName(8<<8 | 0); got != "vd8:0" {
		t.Errorf("expected vd8:0, got %s", got)
	}
}
