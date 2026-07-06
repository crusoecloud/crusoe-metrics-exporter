package collectors

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type PSILine struct {
	Avg10        float64 //stall last 10 seconds
	Avg60        float64 // stall last 1 min
	Avg300       float64 // stall last 5 mins
	TotalSeconds float64
}

type PSIStats struct {
	Some PSILine
	Full PSILine
}

func ParsePSI(path string) (stats *PSIStats, available bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer file.Close()

	stats = &PSIStats{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		var target *PSILine
		switch fields[0] {
		case "some":
			target = &stats.Some
		case "full":
			target = &stats.Full
		default:
			continue
		}

		for _, kv := range fields[1:] {
			key, valStr, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			val, perr := strconv.ParseFloat(valStr, 64)
			if perr != nil {
				return nil, true, fmt.Errorf("psi %s: bad %s=%q: %w", path, key, valStr, perr)
			}
			switch key {
			case "avg10":
				target.Avg10 = val
			case "avg60":
				target.Avg60 = val
			case "avg300":
				target.Avg300 = val
			case "total":
				target.TotalSeconds = val / 1e6
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return stats, true, nil
}
