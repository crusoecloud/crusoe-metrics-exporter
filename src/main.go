package main

import (
	"metrics-exporter/src/collectors"
	"metrics-exporter/src/log"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9500"
	}

	diskStatsPath := os.Getenv("DISKSTATS_PATH")
	if diskStatsPath == "" {
		diskStatsPath = "/host/proc/diskstats"
	}

	mountStatsPath := os.Getenv("MOUNTSTATS_PATH")
	if mountStatsPath == "" {
		// Try both possible locations
		if _, err := os.Stat("/proc/self/mountstats"); err == nil {
			mountStatsPath = "/proc/self/mountstats"
		} else {
			mountStatsPath = "/host/proc/self/mountstats"
		}
	}

	// Create collectors
	diskCollector := collectors.NewDiskStatsCollector(diskStatsPath)
	nfsCollector := collectors.NewNFSStatsCollector(mountStatsPath)

	// Register collectors
	prometheus.MustRegister(diskCollector)
	prometheus.MustRegister(nfsCollector)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	log.Infof("Starting metrics exporter on port %s", port)
	log.Infof("Disk stats path: %s", diskStatsPath)
	log.Infof("Mount stats path: %s", mountStatsPath)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
