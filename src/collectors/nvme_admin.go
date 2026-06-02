package collectors

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// nvmeIoctlAdminCmd is the ioctl command number for NVME_IOCTL_ADMIN_CMD
// (_IOWR('N', 0x41, struct nvme_admin_cmd)), as defined in <linux/nvme_ioctl.h>.
const nvmeIoctlAdminCmd = 0xC0484E41

// nvmeAdminCmd mirrors struct nvme_admin_cmd from <linux/nvme_ioctl.h>.
// Fields are laid out exactly as the kernel expects; unsafe.Sizeof must be 72.
type nvmeAdminCmd struct {
	opcode      uint8
	flags       uint8
	rsvd1       uint16
	nsid        uint32
	cdw2        uint32
	cdw3        uint32
	metadata    uint64
	addr        uint64
	metadataLen uint32
	dataLen     uint32
	cdw10       uint32
	cdw11       uint32
	cdw12       uint32
	cdw13       uint32
	cdw14       uint32
	cdw15       uint32
	timeoutMs   uint32
	result      uint32
}

// ioctlIssuer is a function that issues an ioctl syscall. The real implementation
// uses unix.Syscall; tests inject a fake to avoid needing a real device file.
type ioctlIssuer func(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno)

func realIssuer(fd, cmd, arg uintptr) (uintptr, uintptr, syscall.Errno) {
	return unix.Syscall(unix.SYS_IOCTL, fd, cmd, arg) //nolint:staticcheck // SYS_IOCTL is the correct Linux syscall; deprecation is macOS-only
}

// GetLogPage retrieves NVMe Log Page lid for namespace nsid into buf.
// buf must be at least 512 bytes. Returns an error if the ioctl fails or
// the kernel reports an error status (result != 0).
func GetLogPage(fd uintptr, lid uint8, nsid uint32, buf []byte, issuer ioctlIssuer) error {
	if len(buf) < 512 {
		return fmt.Errorf("buffer too small: need at least 512 bytes, got %d", len(buf))
	}
	if issuer == nil {
		issuer = realIssuer
	}

	numd := uint32(len(buf)/4 - 1) // number of dwords minus 1
	cmd := nvmeAdminCmd{
		opcode:  0x02, // Get Log Page
		nsid:    nsid,
		addr:    uint64(uintptr(unsafe.Pointer(&buf[0]))),
		dataLen: uint32(len(buf)),
		cdw10:   uint32(lid) | (numd << 16),
	}

	_, _, errno := issuer(fd, nvmeIoctlAdminCmd, uintptr(unsafe.Pointer(&cmd)))
	if errno != 0 {
		return fmt.Errorf("nvme ioctl: %w", errno)
	}
	if cmd.result != 0 {
		return fmt.Errorf("nvme admin command failed: status 0x%x", cmd.result)
	}
	return nil
}
