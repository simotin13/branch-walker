package gcapstone

/*
#cgo LDFLAGS: -lcapstone
#include <capstone/capstone.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
	"reflect"
)

const (
	CS_ARCH_ARM   = C.CS_ARCH_ARM     // ARM architecture (including Thumb Thumb-2)
	CS_ARCH_ARM64 = C.CS_ARCH_ARM64   // ARM-64, also called AArch64
	CS_ARCH_X86   = C.CS_ARCH_X86     // X86 architecture (including x86 & x86-64)
	CS_ARCH_RISCV = C.CS_ARCH_RISCV   // RISCV architecture
)
const (
	// Engine modes
	CS_MODE_LITTLE_ENDIAN = C.CS_MODE_LITTLE_ENDIAN // little endian mode (default mode)
	CS_MODE_ARM           = C.CS_MODE_ARM           // 32-bit ARM
	CS_MODE_16            = C.CS_MODE_16            // 16-bit mode (X86)
	CS_MODE_32            = C.CS_MODE_32            // 32-bit mode (X86)
	CS_MODE_64            = C.CS_MODE_64            // 64-bit mode (X86, PPC)
	CS_MODE_THUMB         = C.CS_MODE_THUMB         // ARM's Thumb mode, including Thumb-2
	CS_MODE_MCLASS        = C.CS_MODE_MCLASS        // ARM's Cortex-M series
	CS_MODE_V8            = C.CS_MODE_V8            // ARMv8 A32 encodings for ARM
	CS_MODE_MICRO         = C.CS_MODE_MICRO         // MicroMips mode (MIPS)
	CS_MODE_RISCV32       = C.CS_MODE_RISCV32       // RISCV RV32G
	CS_MODE_RISCV64       = C.CS_MODE_RISCV64       // RISCV RV64G
	CS_MODE_RISCVC        = C.CS_MODE_RISCVC        // RISCV compressed instructure mode
)

type Capstone struct {
	handle C.csh
	arch   int
	mode   int
}

type Instruction struct {
	Address  uint64
	Mnemonic string
	OpStr    string
	Bytes    []byte
}

func New(arch int, mode int) (*Capstone, error) {
	var handle C.csh
	ret := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if ret != C.CS_ERR_OK {
		return nil, fmt.Errorf("Failed to initialize Capstone")
	}
	return &Capstone{handle: handle, arch: arch, mode: mode}, nil
}
func (c *Capstone) Disasm(code []byte, address, count uint64) ([]Instruction, error) {
	var insn *C.cs_insn
	bptr := (*C.uint8_t)(unsafe.Pointer(&code[0]))
	disassembled := C.cs_disasm(
		c.handle,
		bptr,
		C.size_t(len(code)),
		C.uint64_t(address),
		C.size_t(count),
		&insn,
	)
	if disassembled < 1 {
		return nil, fmt.Errorf("Failed to disassemble")
	}
	defer C.cs_free(insn, C.size_t(disassembled))
	// Create a slice, and reflect its header
	var insns []C.cs_insn
	h := (*reflect.SliceHeader)(unsafe.Pointer(&insns))
	// Manually fill in the ptr, len and cap from the raw C data
	h.Data = uintptr(unsafe.Pointer(insn))
	h.Len = int(disassembled)
	h.Cap = int(disassembled)

	instructions := make([]Instruction, disassembled)
	for i, instruction := range insns {
		bslice := make([]byte, instruction.size)
		for i := 0; i < int(instruction.size); i++ {
			bslice[i] = byte(instruction.bytes[i])
		}
	
		instructions[i] = Instruction{
			Address:  uint64(instruction.address),
			Mnemonic: C.GoString(&instruction.mnemonic[0]),
			OpStr:    C.GoString(&instruction.op_str[0]),
			Bytes:    bslice,
		}
	}
	return instructions, nil
}
