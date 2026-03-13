package collectors

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// TestEBPFMapsExist verifies that all maps referenced in Go code exist in the eBPF program.
// This catches issues where map names in C code don't match what Go expects.
func TestEBPFMapsExist(t *testing.T) {
	// Load the eBPF spec from embedded bytecode
	spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(string(objstoreLatencyBPF)))
	if err != nil {
		t.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Maps that the Go code references
	requiredMaps := []string{
		"config_map",             // Used in configurePort()
		"active_requests",        // Internal eBPF map for tracking requests
		"objstore_latency_by_ip", // Used in Collect()
	}

	// Get actual map names from the eBPF program
	actualMaps := getMapNames(spec.Maps)

	// Verify each required map exists
	for _, mapName := range requiredMaps {
		if _, exists := spec.Maps[mapName]; !exists {
			t.Errorf("Required map '%s' not found in eBPF program.\n"+
				"  Expected maps: %v\n"+
				"  Actual maps:   %v\n"+
				"  This usually means the map name in ebpf/objstore_latency.c doesn't match what the Go code expects.",
				mapName, requiredMaps, actualMaps)
		}
	}
}

// TestEBPFProgramsExist verifies that all programs referenced in Go code exist in the eBPF program.
// This catches issues where function names in C code don't match what Go expects.
func TestEBPFProgramsExist(t *testing.T) {
	// Load the eBPF spec from embedded bytecode
	spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(string(objstoreLatencyBPF)))
	if err != nil {
		t.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Programs that the Go code references (from attachKprobes)
	requiredPrograms := []string{
		"tcp_sendmsg_entry",      // Kprobe for tcp_sendmsg
		"tcp_cleanup_rbuf_entry", // Kprobe for tcp_cleanup_rbuf
		"tcp_retransmit_entry",   // Kprobe for tcp_retransmit_skb
	}

	// Get actual program names from the eBPF program
	actualPrograms := getProgramNames(spec.Programs)

	// Verify each required program exists
	for _, progName := range requiredPrograms {
		if _, exists := spec.Programs[progName]; !exists {
			t.Errorf("Required program '%s' not found in eBPF program.\n"+
				"  Expected programs: %v\n"+
				"  Actual programs:   %v\n"+
				"  This usually means the function name in ebpf/objstore_latency.c doesn't match what the Go code expects.",
				progName, requiredPrograms, actualPrograms)
		}
	}
}

// TestEBPFLoadsSuccessfully verifies the eBPF program compiles and loads without errors.
// This is a basic sanity check that the embedded bytecode is valid.
func TestEBPFLoadsSuccessfully(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(strings.NewReader(string(objstoreLatencyBPF)))
	if err != nil {
		t.Fatalf("Failed to load eBPF spec: %v", err)
	}

	if spec == nil {
		t.Fatal("eBPF spec is nil")
	}

	// Verify we have at least some maps and programs
	if len(spec.Maps) == 0 {
		t.Error("eBPF program has no maps")
	}

	if len(spec.Programs) == 0 {
		t.Error("eBPF program has no programs")
	}

	t.Logf("eBPF program loaded successfully with %d maps and %d programs",
		len(spec.Maps), len(spec.Programs))
}

// Helper function to get all map names from a map spec
func getMapNames(maps map[string]*ebpf.MapSpec) []string {
	names := make([]string, 0, len(maps))
	for name := range maps {
		names = append(names, name)
	}
	return names
}

// Helper function to get all program names from a program spec
func getProgramNames(programs map[string]*ebpf.ProgramSpec) []string {
	names := make([]string, 0, len(programs))
	for name := range programs {
		names = append(names, name)
	}
	return names
}
