package collectors

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// procStatValues holds the /proc/stat fields consumed by the guest-health
// collectors. Each has* flag is false when its line is absent or its value is
// unparseable; the error return is reserved for I/O failures, so one bad field
// never discards the others.
type procStatValues struct {
	stealJiffies float64
	procsRunning float64
	procsBlocked float64

	hasSteal        bool
	hasProcsRunning bool
	hasProcsBlocked bool
}

// readProcStat opens and scans /proc/stat once, extracting the aggregate cpu
// line's steal column and the procs_running / procs_blocked counters. It is
// shared by the CPU-steal and I/O-pressure collectors so the file is parsed by
// a single implementation.
func readProcStat(path string) (procStatValues, error) {
	var out procStatValues

	file, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// /proc/stat's intr line carries one counter per IRQ vector and can exceed
	// the 64KB default token size on large hosts. Since procs_running and
	// procs_blocked follow intr, an over-long line would otherwise abort the
	// scan and drop those metrics; 1MB is well above any real line.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "cpu":
			// cpu  user nice system idle iowait irq softirq steal guest guest_nice — steal is fields[8].
			if len(fields) >= 9 {
				if v, perr := strconv.ParseFloat(fields[8], 64); perr == nil {
					out.stealJiffies = v
					out.hasSteal = true
				}
			}
		case "procs_running":
			if v, perr := strconv.ParseFloat(fields[1], 64); perr == nil {
				out.procsRunning = v
				out.hasProcsRunning = true
			}
		case "procs_blocked":
			if v, perr := strconv.ParseFloat(fields[1], 64); perr == nil {
				out.procsBlocked = v
				out.hasProcsBlocked = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}
