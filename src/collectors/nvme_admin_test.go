package collectors

import (
	"errors"
	"syscall"
	"testing"
	"unsafe"
)

// resultSettingIssuer returns a fake issuer that writes the given result field
// back into the admin command struct and returns the given errno.
func resultSettingIssuer(errno syscall.Errno, result uint32) ioctlIssuer {
	return func(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno) {
		c := (*nvmeAdminCmd)(unsafe.Pointer(arg)) //nolint:unsafeptr // test-only; arg is &nvmeAdminCmd on caller's stack
		c.result = result
		return 0, 0, errno
	}
}

func TestGetLogPage_Success(t *testing.T) {
	buf := make([]byte, 512)
	issuer := func(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, 0
	}
	if err := GetLogPage(0, 0x02, 0xFFFFFFFF, buf, issuer); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetLogPage_BufferTooSmall(t *testing.T) {
	buf := make([]byte, 256)
	if err := GetLogPage(0, 0x02, 0, buf, resultSettingIssuer(0, 0)); err == nil {
		t.Fatal("expected error for undersized buffer, got nil")
	}
}

func TestGetLogPage_IoctlEPERM(t *testing.T) {
	buf := make([]byte, 512)
	err := GetLogPage(0, 0x02, 0, buf, resultSettingIssuer(syscall.EPERM, 0))
	if err == nil {
		t.Fatal("expected error for EPERM, got nil")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("expected EPERM in error chain, got: %v", err)
	}
}

func TestGetLogPage_IoctlENOTTY(t *testing.T) {
	buf := make([]byte, 512)
	err := GetLogPage(0, 0x02, 0, buf, resultSettingIssuer(syscall.ENOTTY, 0))
	if err == nil {
		t.Fatal("expected error for ENOTTY, got nil")
	}
	if !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("expected ENOTTY in error chain, got: %v", err)
	}
}

func TestGetLogPage_NonZeroResult(t *testing.T) {
	buf := make([]byte, 512)
	err := GetLogPage(0, 0x02, 0, buf, resultSettingIssuer(0, 0x0201))
	if err == nil {
		t.Fatal("expected error for non-zero command result, got nil")
	}
}

func TestGetLogPage_NilIssuerUsesReal(t *testing.T) {
	// nil issuer falls back to realIssuer; fd=0 is stdin, not an NVMe device,
	// so we expect ENOTTY rather than a panic.
	buf := make([]byte, 512)
	err := GetLogPage(0, 0x02, 0, buf, nil)
	if err == nil {
		t.Fatal("expected error when issuing ioctl against fd=0 (not an nvme device)")
	}
}
