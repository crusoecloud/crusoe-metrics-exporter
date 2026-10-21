package collectors

import (
	"strings"
	"testing"
)

// TestSumDiskStatsAddsEveryPerCPUCopy checks that per-CPU values are summed field by field.
func TestSumDiskStatsAddsEveryPerCPUCopy(t *testing.T) {
	a := diskLatencyStats{ReadCount: 3, WriteCount: 1, ReadBytes: 12288, WriteBytes: 4096,
		TotalReadLatencyNs: 300, TotalWriteLatencyNs: 50, ReadErrorCount: 1, AllocTsCount: 2}
	a.ReadHistogram[0] = 2
	a.ReadHistogram[19] = 1
	a.WriteHistogram[5] = 1
	b := diskLatencyStats{ReadCount: 2, WriteCount: 4, ReadBytes: 8192, WriteBytes: 16384,
		TotalReadLatencyNs: 200, TotalWriteLatencyNs: 400, WriteErrorCount: 3, AllocTsCount: 1}
	b.ReadHistogram[0] = 1
	b.WriteHistogram[5] = 4

	got := sumDiskStats([]diskLatencyStats{a, b, {}})

	if got.ReadCount != 5 || got.WriteCount != 5 || got.ReadBytes != 20480 || got.WriteBytes != 20480 {
		t.Errorf("counts/bytes not summed: %+v", got)
	}
	if got.TotalReadLatencyNs != 500 || got.TotalWriteLatencyNs != 450 {
		t.Errorf("latency not summed: read %d write %d", got.TotalReadLatencyNs, got.TotalWriteLatencyNs)
	}
	if got.ReadHistogram[0] != 3 || got.ReadHistogram[19] != 1 || got.WriteHistogram[5] != 5 {
		t.Errorf("histograms not summed: read %v write %v", got.ReadHistogram, got.WriteHistogram)
	}
	if got.ReadErrorCount != 1 || got.WriteErrorCount != 3 || got.AllocTsCount != 3 {
		t.Errorf("errors/alloc-ts not summed: %+v", got)
	}
}

// TestSumDiskStatsEmpty checks that no per-CPU values gives zero stats.
func TestSumDiskStatsEmpty(t *testing.T) {
	if got := sumDiskStats(nil); got != (diskLatencyStats{}) {
		t.Errorf("expected zero stats, got %+v", got)
	}
}

// TestParseVirtioBlkMajor reads the virtblk major from the Block devices section only.
func TestParseVirtioBlkMajor(t *testing.T) {
	procDevices := `Character devices:
  1 mem
  4 /dev/vc/0
252 virtblk_char_not_this
Block devices:
  7 loop
  8 sd
  9 md
252 virtblk
253 device-mapper
259 blkext
`
	if got := parseVirtioBlkMajor(strings.NewReader(procDevices)); got != 252 {
		t.Errorf("expected 252, got %d", got)
	}
}

// TestParseVirtioBlkMajorAbsent returns 0 when no virtio-blk driver is registered.
func TestParseVirtioBlkMajorAbsent(t *testing.T) {
	procDevices := "Character devices:\n  1 mem\nBlock devices:\n  7 loop\n259 blkext\n"
	if got := parseVirtioBlkMajor(strings.NewReader(procDevices)); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

// TestParseVirtioBlkMajorIgnoresCharacterSection doesn't take a char device named virtblk.
func TestParseVirtioBlkMajorIgnoresCharacterSection(t *testing.T) {
	procDevices := "Character devices:\n250 virtblk\nBlock devices:\n  7 loop\n"
	if got := parseVirtioBlkMajor(strings.NewReader(procDevices)); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}
