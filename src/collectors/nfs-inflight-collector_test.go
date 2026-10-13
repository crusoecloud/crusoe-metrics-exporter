package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const inflightMetricName = MetricPrefix + "nfs_rpc_inflight_requests"

// taskLine is one realistic line from a sunrpc rpc_clnt tasks file.
const taskLine = "1bb85060ee 8801      0 0x16 12 0x2 0xb316e13e    59973 nfs_pgio_common_ops [nfs] nfsv3 READ a:xprt_timer [sunrpc] q:xprt_pending\n"

func writeInflightFixture(t *testing.T, mountinfo string, sbFiles map[string]string, tasks map[string]string) *NFSInflightCollector {
	t.Helper()
	dir := t.TempDir()

	mountInfoPath := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(mountInfoPath, []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}

	vastnfsDir := filepath.Join(dir, "vastnfs")
	if err := os.MkdirAll(filepath.Join(vastnfsDir, "nfs_sb"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range sbFiles {
		if err := os.WriteFile(filepath.Join(vastnfsDir, "nfs_sb", name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	sunrpcDir := filepath.Join(dir, "sunrpc")
	for clntDirName, content := range tasks {
		clntDir := filepath.Join(sunrpcDir, "rpc_clnt", clntDirName)
		if err := os.MkdirAll(clntDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(clntDir, "tasks"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return NewNFSInflightCollector(mountInfoPath, vastnfsDir, sunrpcDir)
}

func collectInflight(t *testing.T, c *NFSInflightCollector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]float64)
	for _, fam := range families {
		if fam.GetName() != inflightMetricName {
			continue
		}
		for _, m := range fam.GetMetric() {
			var volumeID string
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "volume_id" {
					volumeID = lp.GetValue()
				}
			}
			result[volumeID] = m.GetGauge().GetValue()
		}
	}
	return result
}

func metricCount(fams []*dto.MetricFamily, name string) int {
	for _, fam := range fams {
		if fam.GetName() == name {
			return len(fam.GetMetric())
		}
	}
	return 0
}

func TestInflightPerVolume(t *testing.T) {
	mountinfo := "337 30 0:50 / /mnt/1 rw,relatime shared:300 - nfs 172.27.255.2:/volumes/a7126795-5476-4ac6-a65f-e4423e4c1774 rw,vers=3\n" +
		"382 30 0:51 / /mnt/2 rw,relatime shared:323 - nfs 172.27.255.2:/volumes/f2471263-23ba-46b8-9653-d020630fa1cc rw,vers=3\n" +
		"30 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
	sbFiles := map[string]string{
		"0": "sb_id: 0:50\nrpc_id: 2\nacl_id: 3\nnfs_id: 3000\n",
		"1": "sb_id: 0:51\nrpc_id: 13\nacl_id: 14\nnfs_id: 3001\n",
	}
	tasks := map[string]string{
		"2": taskLine + taskLine + taskLine, // rpc_id 2  -> dir "2"
		"d": taskLine,                       // rpc_id 13 -> dir "d" (hex)
	}
	c := writeInflightFixture(t, mountinfo, sbFiles, tasks)

	got := collectInflight(t, c)
	if got["a7126795-5476-4ac6-a65f-e4423e4c1774"] != 3 {
		t.Errorf("volume 1 inflight = %v, want 3", got["a7126795-5476-4ac6-a65f-e4423e4c1774"])
	}
	if got["f2471263-23ba-46b8-9653-d020630fa1cc"] != 1 {
		t.Errorf("volume 2 inflight = %v, want 1", got["f2471263-23ba-46b8-9653-d020630fa1cc"])
	}
}

func TestInflightIdleVolumeReadsZero(t *testing.T) {
	mountinfo := "337 30 0:50 / /mnt/1 rw - nfs 172.27.255.2:/volumes/a7126795-5476-4ac6-a65f-e4423e4c1774 rw\n"
	sbFiles := map[string]string{"0": "sb_id: 0:50\nrpc_id: 2\nnfs_id: 3000\n"}
	tasks := map[string]string{"2": ""}
	c := writeInflightFixture(t, mountinfo, sbFiles, tasks)

	got := collectInflight(t, c)
	if v, ok := got["a7126795-5476-4ac6-a65f-e4423e4c1774"]; !ok || v != 0 {
		t.Errorf("idle volume inflight = %v (present=%v), want explicit 0", v, ok)
	}
}

func TestInflightSharedSuperblockStampsAllVolumes(t *testing.T) {
	// Two volumes on one superblock (no nosharetransport): both report the
	// pooled task count.
	mountinfo := "337 30 0:50 / /mnt/1 rw - nfs s:/volumes/a7126795-5476-4ac6-a65f-e4423e4c1774 rw\n" +
		"382 30 0:50 / /mnt/2 rw - nfs s:/volumes/f2471263-23ba-46b8-9653-d020630fa1cc rw\n"
	sbFiles := map[string]string{"0": "sb_id: 0:50\nrpc_id: 2\nnfs_id: 3000\n"}
	tasks := map[string]string{"2": taskLine + taskLine}
	c := writeInflightFixture(t, mountinfo, sbFiles, tasks)

	got := collectInflight(t, c)
	for _, vol := range []string{"a7126795-5476-4ac6-a65f-e4423e4c1774", "f2471263-23ba-46b8-9653-d020630fa1cc"} {
		if got[vol] != 2 {
			t.Errorf("volume %s inflight = %v, want 2 (pooled)", vol, got[vol])
		}
	}
}

func TestInflightSubpathMountsKeepMountstatsShape(t *testing.T) {
	// Subpath mounts keep the raw everything-after-/volumes/ volume_id so
	// the series join with the existing mountstats collectors' labels.
	mountinfo := "337 30 0:50 / /mnt/1 rw - nfs s:/volumes/a7126795-5476-4ac6-a65f-e4423e4c1774/data rw\n" +
		"382 30 0:51 / /mnt/2 rw - nfs s:/volumes/a7126795-5476-4ac6-a65f-e4423e4c1774/logs rw\n"
	sbFiles := map[string]string{
		"0": "sb_id: 0:50\nrpc_id: 2\nnfs_id: 3000\n",
		"1": "sb_id: 0:51\nrpc_id: 3\nnfs_id: 3001\n",
	}
	tasks := map[string]string{"2": taskLine, "3": taskLine + taskLine}
	c := writeInflightFixture(t, mountinfo, sbFiles, tasks)

	got := collectInflight(t, c)
	if got["a7126795-5476-4ac6-a65f-e4423e4c1774/data"] != 1 || got["a7126795-5476-4ac6-a65f-e4423e4c1774/logs"] != 2 {
		t.Errorf("got %v, want .../data = 1 and .../logs = 2", got)
	}
}

func TestInflightMissingDebugfsIsSilent(t *testing.T) {
	dir := t.TempDir()
	mountInfoPath := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(mountInfoPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewNFSInflightCollector(mountInfoPath, filepath.Join(dir, "missing"), filepath.Join(dir, "missing2"))

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if n := metricCount(families, inflightMetricName); n != 0 {
		t.Errorf("expected no inflight series without debugfs, got %d", n)
	}
}

func TestInflightVanishedClientSkipped(t *testing.T) {
	// sb entry maps to an rpc_clnt dir that no longer exists: skip, don't error.
	mountinfo := "337 30 0:50 / /mnt/1 rw - nfs s:/volumes/a7126795-5476-4ac6-a65f-e4423e4c1774 rw\n" +
		"382 30 0:51 / /mnt/2 rw - nfs s:/volumes/f2471263-23ba-46b8-9653-d020630fa1cc rw\n"
	sbFiles := map[string]string{
		"0": "sb_id: 0:50\nrpc_id: 2\nnfs_id: 3000\n",
		"1": "sb_id: 0:51\nrpc_id: 99\nnfs_id: 3001\n", // no tasks dir
	}
	tasks := map[string]string{"2": taskLine}
	c := writeInflightFixture(t, mountinfo, sbFiles, tasks)

	got := collectInflight(t, c)
	if got["a7126795-5476-4ac6-a65f-e4423e4c1774"] != 1 {
		t.Errorf("surviving volume inflight = %v, want 1", got["a7126795-5476-4ac6-a65f-e4423e4c1774"])
	}
	if _, ok := got["f2471263-23ba-46b8-9653-d020630fa1cc"]; ok {
		t.Errorf("vanished-client volume should emit no series, got %v", got["f2471263-23ba-46b8-9653-d020630fa1cc"])
	}
}

