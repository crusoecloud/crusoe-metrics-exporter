// NVMe controller collector — reports controller-level health for passthrough
// NVMe drives (SMART/Health Log Page 0x02 + sysfs identity).
//
// Design
//
//   - Probe-once at startup. The collector registers only if at least one
//     /sys/class/nvme/nvmeN entry exists AND /dev/nvmeN can be opened. This
//     differs from sibling collectors, which register unconditionally and
//     surface failures per scrape. Justified because /dev/nvme* permissions
//     are fixed by the deployment model (privileged container or root unit)
//     and don't change at runtime.
//
//   - Device discovery and identity (serial / model / firmware_rev) are
//     cached together and refreshed on the nvmeStateTTL cadence. Hot-plug
//     is not a supported scenario for passthrough NVMe in our fleet, so
//     the cadence exists purely to pick up in-place firmware updates and
//     survive transient sysfs hiccups. On refresh failure the timestamp
//     is not advanced, so the next scrape retries.
//
//   - SMART counters are 128-bit on the wire; we read the low 64 bits, which
//     is sufficient for any realistic operational lifetime.
//
//   - A per-scrape collection_errors_total gauge surfaces ioctl failures
//     without dropping the rest of the scrape.
package collectors

import (
	"encoding/binary"
	"fmt"
	"metrics-exporter/src/log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// nvmeDeviceRe matches controller directory names under /sys/class/nvme.
// Anchored to digits-only so sibling entries like "nvme-subsystem0" are skipped.
var nvmeDeviceRe = regexp.MustCompile(`^nvme\d+$`)

// nvmeStateTTL bounds how long the cached device list and identity map are
// reused before a fresh sysfs read. See the package doc comment for the
// rationale (firmware updates, transient sysfs hiccups; hot-plug is not in
// scope).
const nvmeStateTTL = 24 * time.Hour

// Identity fields are space-padded ASCII in the NVMe identify-controller
// structure (MN 40 bytes, SN 20 bytes, FR 8 bytes); the kernel exposes them
// via sysfs and we strip padding for label use.
type nvmeIdentity struct {
	Serial      string
	Model       string
	FirmwareRev string
}

// criticalWarningBits enumerates the six defined bits of the SMART/Health Log
// critical_warning byte (NVMe Base Spec §5.14.1.2, Table 216).
var criticalWarningBits = []struct {
	name string
	bit  uint8
}{
	{"spare_low", 0},
	{"temperature", 1},
	{"reliability", 2},
	{"readonly", 3},
	{"volatile_backup_failed", 4},
	{"pmr_unreliable", 5},
}

// NVMeCollector reports NVMe controller health for passthrough drives.
type NVMeCollector struct {
	nvmeClassPath string
	nvmeDevPath   string
	smartIssuer   ioctlIssuer // nil → realIssuer; overridden in tests

	infoDesc            *prometheus.Desc
	criticalWarningDesc *prometheus.Desc
	mediaErrorsDesc      *prometheus.Desc
	errorLogEntriesDesc  *prometheus.Desc
	percentageUsedDesc   *prometheus.Desc
	availableSpareDesc   *prometheus.Desc
	powerOnHoursDesc     *prometheus.Desc
	collectionErrorsDesc *prometheus.Desc

	mu            sync.Mutex
	devices       []string
	identityCache map[string]nvmeIdentity
	lastRefreshAt time.Time
}

func NewNVMeCollector() *NVMeCollector {
	return &NVMeCollector{
		nvmeClassPath: "/sys/class/nvme",
		nvmeDevPath:   "/dev",
		infoDesc: prometheus.NewDesc(
			MetricPrefix+"nvme_info",
			"NVMe controller identity; value is always 1, information is in the labels.",
			[]string{"device", "serial", "model", "firmware_rev"}, nil,
		),
		criticalWarningDesc: prometheus.NewDesc(
			MetricPrefix+"nvme_smart_critical_warning",
			"NVMe SMART critical warning bit (0=clear, 1=set). Any value of 1 is a platform emergency.",
			[]string{"device", "serial", "bit"}, nil,
		),
		mediaErrorsDesc: prometheus.NewDesc(
			MetricPrefix+"nvme_media_errors_total",
			"Uncorrectable media and data integrity errors reported by the NVMe drive.",
			[]string{"device", "serial"}, nil,
		),
		errorLogEntriesDesc: prometheus.NewDesc(
			MetricPrefix+"nvme_error_log_entries_total",
			"Number of error information log entries over the lifetime of the drive.",
			[]string{"device", "serial"}, nil,
		),
		percentageUsedDesc: prometheus.NewDesc(
			MetricPrefix+"nvme_percentage_used",
			"Vendor estimate of NVM subsystem life consumed (0–255; 100 = rated endurance reached).",
			[]string{"device", "serial"}, nil,
		),
		availableSpareDesc: prometheus.NewDesc(
			MetricPrefix+"nvme_available_spare",
			"Remaining spare capacity as a percentage of the original (0–100).",
			[]string{"device", "serial"}, nil,
		),
		powerOnHoursDesc: prometheus.NewDesc(
			MetricPrefix+"nvme_power_on_hours",
			"Hours the NVMe controller has been powered on over its physical lifetime.",
			[]string{"device", "serial"}, nil,
		),
		collectionErrorsDesc: prometheus.NewDesc(
			MetricPrefix+"nvme_collection_errors_total",
			"Total number of errors encountered during NVMe SMART collection per scrape.",
			nil, nil,
		),
		identityCache: make(map[string]nvmeIdentity),
	}
}

// Probe decides whether the collector should be registered on this host. It
// returns ok=true only when at least one passthrough NVMe controller is
// visible AND the process can open the corresponding device file; any other
// outcome (no controllers, EACCES/EPERM, ENOENT) returns ok=false with a
// reason suitable for logging.
//
// Permission state on /dev/nvme* does not change at runtime in our deployment
// model (privileged container or root systemd unit), so a one-shot startup
// probe is sufficient. This is intentionally different from the rest of the
// collectors, which register unconditionally and surface failures per scrape.
func (c *NVMeCollector) Probe() (ok bool, reason string) {
	devices, err := c.discoverDevices()
	if err != nil {
		return false, fmt.Sprintf("sysfs read failed (%s): %v", c.nvmeClassPath, err)
	}
	if len(devices) == 0 {
		return false, "no passthrough NVMe controllers found"
	}
	devFile := filepath.Join(c.nvmeDevPath, devices[0])
	f, err := os.OpenFile(devFile, os.O_RDONLY, 0)
	if err != nil {
		return false, fmt.Sprintf("cannot open %s: %v", devFile, err)
	}
	f.Close()
	return true, ""
}

func (c *NVMeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.infoDesc
	ch <- c.criticalWarningDesc
	ch <- c.mediaErrorsDesc
	ch <- c.errorLogEntriesDesc
	ch <- c.percentageUsedDesc
	ch <- c.availableSpareDesc
	ch <- c.powerOnHoursDesc
	ch <- c.collectionErrorsDesc
}

func (c *NVMeCollector) Collect(ch chan<- prometheus.Metric) {
	devices, identities, err := c.snapshotState()
	if err != nil {
		log.Errorf("NVMe: failed to refresh device state: %v", err)
		return
	}

	collectionErrors := 0.0
	for _, dev := range devices {
		id := identities[dev]
		if id == (nvmeIdentity{}) {
			log.Warnf("NVMe: no cached identity for %s; metrics will carry empty labels", dev)
		}
		ch <- prometheus.MustNewConstMetric(
			c.infoDesc, prometheus.GaugeValue, 1,
			dev, id.Serial, id.Model, id.FirmwareRev,
		)

		devPath := filepath.Join(c.nvmeDevPath, dev)
		smart, err := getSmartLog(devPath, c.smartIssuer)
		if err != nil {
			log.Warnf("NVMe: failed to read SMART log for %s: %v", dev, err)
			collectionErrors++
			continue
		}

		for _, b := range criticalWarningBits {
			val := float64((smart.criticalWarning >> b.bit) & 1)
			ch <- prometheus.MustNewConstMetric(
				c.criticalWarningDesc, prometheus.GaugeValue, val,
				dev, id.Serial, b.name,
			)
		}

		ch <- prometheus.MustNewConstMetric(
			c.mediaErrorsDesc, prometheus.CounterValue,
			float64(smart.mediaErrors), dev, id.Serial,
		)
		ch <- prometheus.MustNewConstMetric(
			c.errorLogEntriesDesc, prometheus.CounterValue,
			float64(smart.numErrLogEntries), dev, id.Serial,
		)
		ch <- prometheus.MustNewConstMetric(
			c.percentageUsedDesc, prometheus.GaugeValue,
			float64(smart.percentageUsed), dev, id.Serial,
		)
		ch <- prometheus.MustNewConstMetric(
			c.availableSpareDesc, prometheus.GaugeValue,
			float64(smart.availableSpare), dev, id.Serial,
		)
		ch <- prometheus.MustNewConstMetric(
			c.powerOnHoursDesc, prometheus.GaugeValue,
			float64(smart.powerOnHours), dev, id.Serial,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.collectionErrorsDesc, prometheus.GaugeValue, collectionErrors,
	)
}

// discoverDevices returns the controller names visible under nvmeClassPath
// (e.g. ["nvme0", "nvme1"]). Empty slice — no error — means no passthrough
// controllers (virtio-only VMs land here).
func (c *NVMeCollector) discoverDevices() ([]string, error) {
	entries, err := os.ReadDir(c.nvmeClassPath)
	if err != nil {
		return nil, err
	}
	var devices []string
	for _, e := range entries {
		if nvmeDeviceRe.MatchString(e.Name()) {
			devices = append(devices, e.Name())
		}
	}
	sort.Strings(devices)
	return devices, nil
}

// snapshotState returns the cached device list and identity map, refreshing
// both from sysfs at most once per nvmeStateTTL. The refresh rebuilds the
// identity map from scratch to pick up in-place firmware updates and drop
// devices that have disappeared. On discovery failure the timestamp is not
// advanced so the next scrape retries; individual identity-read failures
// are logged and leave that device with empty labels.
func (c *NVMeCollector) snapshotState() ([]string, map[string]nvmeIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fresh := !c.lastRefreshAt.IsZero() && time.Since(c.lastRefreshAt) < nvmeStateTTL
	if !fresh {
		devices, err := c.discoverDevices()
		if err != nil {
			return nil, nil, err
		}
		newIdentities := make(map[string]nvmeIdentity, len(devices))
		for _, dev := range devices {
			id, err := readNVMeIdentity(filepath.Join(c.nvmeClassPath, dev))
			if err != nil {
				log.Warnf("NVMe: failed to read identity for %s: %v", dev, err)
				continue
			}
			newIdentities[dev] = id
		}
		c.devices = devices
		c.identityCache = newIdentities
		c.lastRefreshAt = time.Now()
	}

	devicesCopy := make([]string, len(c.devices))
	copy(devicesCopy, c.devices)
	identitiesCopy := make(map[string]nvmeIdentity, len(c.identityCache))
	for k, v := range c.identityCache {
		identitiesCopy[k] = v
	}
	return devicesCopy, identitiesCopy, nil
}

// NVMe SMART/Health Log Page 0x02 byte offsets (NVMe Base Spec §5.14.1.2).
const (
	smartOffCriticalWarning  = 0
	smartOffAvailableSpare   = 3
	smartOffPercentageUsed   = 5
	smartOffPowerOnHours     = 128
	smartOffMediaErrors      = 160
	smartOffNumErrLogEntries = 176
)

type smartFields struct {
	criticalWarning  uint8
	availableSpare   uint8
	percentageUsed   uint8
	powerOnHours     uint64
	mediaErrors      uint64
	numErrLogEntries uint64
}

// parseSmartBuf extracts fields from a 512-byte SMART/Health log response.
// All 128-bit counters are read as their low 64 bits (sufficient for operational lifetimes).
func parseSmartBuf(buf [512]byte) smartFields {
	return smartFields{
		criticalWarning:  buf[smartOffCriticalWarning],
		availableSpare:   buf[smartOffAvailableSpare],
		percentageUsed:   buf[smartOffPercentageUsed],
		powerOnHours:     binary.LittleEndian.Uint64(buf[smartOffPowerOnHours : smartOffPowerOnHours+8]),
		mediaErrors:      binary.LittleEndian.Uint64(buf[smartOffMediaErrors : smartOffMediaErrors+8]),
		numErrLogEntries: binary.LittleEndian.Uint64(buf[smartOffNumErrLogEntries : smartOffNumErrLogEntries+8]),
	}
}

// getSmartLog opens devPath and reads SMART/Health Log Page 0x02.
// issuer is the ioctl back-end; pass nil to use the real kernel syscall.
// The Linux NVMe driver accepts admin commands on a read-only fd. If a strict
// LSM policy or unusual vendor driver requires write access, use os.O_RDWR.
func getSmartLog(devPath string, issuer ioctlIssuer) (smartFields, error) {
	f, err := os.Open(devPath)
	if err != nil {
		return smartFields{}, err
	}
	defer f.Close()

	var buf [512]byte
	if err := GetLogPage(f.Fd(), 0x02, 0xFFFFFFFF, buf[:], issuer); err != nil {
		return smartFields{}, err
	}
	return parseSmartBuf(buf), nil
}

func readNVMeIdentity(sysfsPath string) (nvmeIdentity, error) {
	read := func(field string) (string, error) {
		b, err := os.ReadFile(filepath.Join(sysfsPath, field))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	serial, err := read("serial")
	if err != nil {
		return nvmeIdentity{}, err
	}
	model, err := read("model")
	if err != nil {
		return nvmeIdentity{}, err
	}
	fw, err := read("firmware_rev")
	if err != nil {
		return nvmeIdentity{}, err
	}
	return nvmeIdentity{Serial: serial, Model: model, FirmwareRev: fw}, nil
}
