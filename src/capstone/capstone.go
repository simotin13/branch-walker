package gcapstone

/*
#cgo LDFLAGS: -lcapstone
#include <capstone/capstone.h>
*/
import "C"
import (
	"fmt"
	"reflect"
	"unsafe"
)

type Errno int

// Getter for the last Errno from the engine. Normal code shouldn't need to
// access this directly, but it's exported just in case.
func (e *Capstone) Errno() error { return Errno(C.cs_errno(e.handle)) }

func (e Errno) Error() string {
	s := C.GoString(C.cs_strerror(C.cs_err(e)))
	if s == "" {
		return fmt.Sprintf("Internal Error: No Error string for Errno %v", e)
	}
	return s
}

var (
	ErrOK       = Errno(0)  // No error: everything was fine
	ErrMem      = Errno(1)  // Out-Of-Memory error: cs_open(), cs_disasm()
	ErrArch     = Errno(2)  // Unsupported architecture: cs_open()
	ErrHandle   = Errno(3)  // Invalid handle: cs_op_count(), cs_op_index()
	ErrCsh      = Errno(4)  // Invalid csh argument: cs_close(), cs_errno(), cs_option()
	ErrMode     = Errno(5)  // Invalid/unsupported mode: cs_open()
	ErrOption   = Errno(6)  // Invalid/unsupported option: cs_option()
	ErrDetail   = Errno(7)  // Information is unavailable because detail option is OFF
	ErrMemSetup = Errno(8)  // Dynamic memory management uninitialized (see CS_OPT_MEM)
	ErrVersion  = Errno(9)  // Unsupported version (bindings)
	ErrDiet     = Errno(10) // Access irrelevant data in "diet" engine
	ErrSkipdata = Errno(11) // Access irrelevant data for "data" instruction in SKIPDATA mode
	ErrX86ATT   = Errno(12) // X86 AT&T syntax is unsupported (opt-out at compile time)
	ErrX86Intel = Errno(13) // X86 Intel syntax is unsupported (opt-out at compile time)

)

const CS_SUPPORT_DIET = C.CS_SUPPORT_DIET
const CS_SUPPORT_X86_REDUCE = C.CS_SUPPORT_X86_REDUCE

// Since this is a build-time option for the C lib, it seems logical to have
// this as a static flag.
// Diet Mode Changes:
// - No regs_read, regs_written or groups
// - No response to reg_name or insn_name
// - No mnemonic or op_str
// If you want to see any operands in diet mode, then you need CS_DETAIL.
var dietMode = bool(C.cs_support(CS_SUPPORT_DIET))

const (
	X86_OP_INVALID = C.X86_OP_INVALID
	X86_OP_REG     = C.X86_OP_REG
	X86_OP_IMM     = C.X86_OP_IMM
	X86_OP_MEM     = C.X86_OP_MEM
)

const (
	X86_GRP_INVALID         = C.X86_GRP_INVALID
	X86_GRP_JUMP            = C.X86_GRP_JUMP
	X86_GRP_CALL            = C.X86_GRP_CALL
	X86_GRP_RET             = C.X86_GRP_RET
	X86_GRP_INT             = C.X86_GRP_INT
	X86_GRP_IRET            = C.X86_GRP_IRET
	X86_GRP_PRIVILEGE       = C.X86_GRP_PRIVILEGE
	X86_GRP_BRANCH_RELATIVE = C.X86_GRP_BRANCH_RELATIVE
	X86_GRP_VM              = C.X86_GRP_VM
	X86_GRP_3DNOW           = C.X86_GRP_3DNOW
	X86_GRP_AES             = C.X86_GRP_AES
	X86_GRP_ADX             = C.X86_GRP_ADX
	X86_GRP_AVX             = C.X86_GRP_AVX
	X86_GRP_AVX2            = C.X86_GRP_AVX2
	X86_GRP_AVX512          = C.X86_GRP_AVX512
	X86_GRP_BMI             = C.X86_GRP_BMI
	X86_GRP_BMI2            = C.X86_GRP_BMI2
	X86_GRP_CMOV            = C.X86_GRP_CMOV
	X86_GRP_F16C            = C.X86_GRP_F16C
	X86_GRP_FMA             = C.X86_GRP_FMA
	X86_GRP_FMA4            = C.X86_GRP_FMA4
	X86_GRP_FSGSBASE        = C.X86_GRP_FSGSBASE
	X86_GRP_HLE             = C.X86_GRP_HLE
	X86_GRP_MMX             = C.X86_GRP_MMX
	X86_GRP_MODE32          = C.X86_GRP_MODE32
	X86_GRP_MODE64          = C.X86_GRP_MODE64
	X86_GRP_RTM             = C.X86_GRP_RTM
	X86_GRP_SHA             = C.X86_GRP_SHA
	X86_GRP_SSE1            = C.X86_GRP_SSE1
	X86_GRP_SSE2            = C.X86_GRP_SSE2
	X86_GRP_SSE3            = C.X86_GRP_SSE3
	X86_GRP_SSE41           = C.X86_GRP_SSE41
	X86_GRP_SSE42           = C.X86_GRP_SSE42
	X86_GRP_SSE4A           = C.X86_GRP_SSE4A
	X86_GRP_SSSE3           = C.X86_GRP_SSSE3
	X86_GRP_PCLMUL          = C.X86_GRP_PCLMUL
	X86_GRP_XOP             = C.X86_GRP_XOP
	X86_GRP_CDI             = C.X86_GRP_CDI
	X86_GRP_ERI             = C.X86_GRP_ERI
	X86_GRP_TBM             = C.X86_GRP_TBM
	X86_GRP_16BITMODE       = C.X86_GRP_16BITMODE
	X86_GRP_NOT64BITMODE    = C.X86_GRP_NOT64BITMODE
	X86_GRP_SGX             = C.X86_GRP_SGX
	X86_GRP_DQI             = C.X86_GRP_DQI
	X86_GRP_BWI             = C.X86_GRP_BWI
	X86_GRP_PFI             = C.X86_GRP_PFI
	X86_GRP_VLX             = C.X86_GRP_VLX
	X86_GRP_SMAP            = C.X86_GRP_SMAP
	X86_GRP_NOVLX           = C.X86_GRP_NOVLX
	X86_GRP_FPU             = C.X86_GRP_FPU
	X86_GRP_ENDING          = C.X86_GRP_ENDING
)

const (
	CS_ARCH_ARM = C.CS_ARCH_ARM // ARM architecture (including Thumb Thumb-2)
	//CS_ARCH_ARM64 = C.CS_ARCH_ARM64 // ARM-64, also called AArch64
	CS_ARCH_X86   = C.CS_ARCH_X86   // X86 architecture (including x86 & x86-64)
	CS_ARCH_RISCV = C.CS_ARCH_RISCV // RISCV architecture
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

const (
	RISCV_REG_X0   = C.RISCV_REG_X0
	RISCV_REG_ZERO = C.RISCV_REG_ZERO
	RISCV_REG_X1   = C.RISCV_REG_X1
	RISCV_REG_RA   = C.RISCV_REG_RA
	RISCV_REG_X2   = C.RISCV_REG_X2
	RISCV_REG_SP   = C.RISCV_REG_SP
	RISCV_REG_X3   = C.RISCV_REG_X3
	RISCV_REG_GP   = C.RISCV_REG_GP
	RISCV_REG_X4   = C.RISCV_REG_X4
	RISCV_REG_TP   = C.RISCV_REG_TP
	RISCV_REG_X5   = C.RISCV_REG_X5
	RISCV_REG_T0   = C.RISCV_REG_T0
	RISCV_REG_X6   = C.RISCV_REG_X6
	RISCV_REG_T1   = C.RISCV_REG_T1
	RISCV_REG_X7   = C.RISCV_REG_X7
	RISCV_REG_T2   = C.RISCV_REG_T2
	RISCV_REG_X8   = C.RISCV_REG_X8
	RISCV_REG_S0   = C.RISCV_REG_S0
	RISCV_REG_FP   = C.RISCV_REG_FP
	RISCV_REG_X9   = C.RISCV_REG_X9
	RISCV_REG_S1   = C.RISCV_REG_S1
	RISCV_REG_X10  = C.RISCV_REG_X10
	RISCV_REG_A0   = C.RISCV_REG_A0
	RISCV_REG_X11  = C.RISCV_REG_X11
	RISCV_REG_A1   = C.RISCV_REG_A1
	RISCV_REG_X12  = C.RISCV_REG_X12
	RISCV_REG_A2   = C.RISCV_REG_A2
	RISCV_REG_X13  = C.RISCV_REG_X13
	RISCV_REG_A3   = C.RISCV_REG_A3
	RISCV_REG_X14  = C.RISCV_REG_X14
	RISCV_REG_A4   = C.RISCV_REG_A4
	RISCV_REG_X15  = C.RISCV_REG_X15
	RISCV_REG_A5   = C.RISCV_REG_A5
	RISCV_REG_X16  = C.RISCV_REG_X16
	RISCV_REG_A6   = C.RISCV_REG_A6
	RISCV_REG_X17  = C.RISCV_REG_X17
	RISCV_REG_A7   = C.RISCV_REG_A7
	RISCV_REG_X18  = C.RISCV_REG_X18
	RISCV_REG_S2   = C.RISCV_REG_S2
	RISCV_REG_X19  = C.RISCV_REG_X19
	RISCV_REG_S3   = C.RISCV_REG_S3
	RISCV_REG_X20  = C.RISCV_REG_X20
	RISCV_REG_S4   = C.RISCV_REG_S4
	RISCV_REG_X21  = C.RISCV_REG_X21
	RISCV_REG_S5   = C.RISCV_REG_S5
	RISCV_REG_X22  = C.RISCV_REG_X22
	RISCV_REG_S6   = C.RISCV_REG_S6
	RISCV_REG_X23  = C.RISCV_REG_X23
	RISCV_REG_S7   = C.RISCV_REG_S7
	RISCV_REG_X24  = C.RISCV_REG_X24
	RISCV_REG_S8   = C.RISCV_REG_S8
	RISCV_REG_X25  = C.RISCV_REG_X25
	RISCV_REG_S9   = C.RISCV_REG_S9
	RISCV_REG_X26  = C.RISCV_REG_X26
	RISCV_REG_S10  = C.RISCV_REG_S10
	RISCV_REG_X27  = C.RISCV_REG_X27
	RISCV_REG_S11  = C.RISCV_REG_S11
	RISCV_REG_X28  = C.RISCV_REG_X28
	RISCV_REG_T3   = C.RISCV_REG_T3
	RISCV_REG_X29  = C.RISCV_REG_X29
	RISCV_REG_T4   = C.RISCV_REG_T4
	RISCV_REG_X30  = C.RISCV_REG_X30
	RISCV_REG_T5   = C.RISCV_REG_T5
	RISCV_REG_X31  = C.RISCV_REG_X31
	RISCV_REG_T6   = C.RISCV_REG_T6

	// float
	RISCV_REG_F0_32  = C.RISCV_REG_F0_32
	RISCV_REG_F0_64  = C.RISCV_REG_F0_64
	RISCV_REG_F1_32  = C.RISCV_REG_F1_32
	RISCV_REG_F1_64  = C.RISCV_REG_F1_64
	RISCV_REG_F2_32  = C.RISCV_REG_F2_32
	RISCV_REG_F2_64  = C.RISCV_REG_F2_64
	RISCV_REG_F3_32  = C.RISCV_REG_F3_32
	RISCV_REG_F3_64  = C.RISCV_REG_F3_64
	RISCV_REG_F4_32  = C.RISCV_REG_F4_32
	RISCV_REG_F4_64  = C.RISCV_REG_F4_64
	RISCV_REG_F5_32  = C.RISCV_REG_F5_32
	RISCV_REG_F5_64  = C.RISCV_REG_F5_64
	RISCV_REG_F6_32  = C.RISCV_REG_F6_32
	RISCV_REG_F6_64  = C.RISCV_REG_F6_64
	RISCV_REG_F7_32  = C.RISCV_REG_F7_32
	RISCV_REG_F7_64  = C.RISCV_REG_F7_64
	RISCV_REG_F8_32  = C.RISCV_REG_F8_32
	RISCV_REG_F8_64  = C.RISCV_REG_F8_64
	RISCV_REG_F9_32  = C.RISCV_REG_F9_32
	RISCV_REG_F9_64  = C.RISCV_REG_F9_64
	RISCV_REG_F10_32 = C.RISCV_REG_F10_32
	RISCV_REG_F10_64 = C.RISCV_REG_F10_64
	RISCV_REG_F11_32 = C.RISCV_REG_F11_32
	RISCV_REG_F11_64 = C.RISCV_REG_F11_64
	RISCV_REG_F12_32 = C.RISCV_REG_F12_32
	RISCV_REG_F12_64 = C.RISCV_REG_F12_64
	RISCV_REG_F13_32 = C.RISCV_REG_F13_32
	RISCV_REG_F13_64 = C.RISCV_REG_F13_64
	RISCV_REG_F14_32 = C.RISCV_REG_F14_32
	RISCV_REG_F14_64 = C.RISCV_REG_F14_64
	RISCV_REG_F15_32 = C.RISCV_REG_F15_32
	RISCV_REG_F15_64 = C.RISCV_REG_F15_64
	RISCV_REG_F16_32 = C.RISCV_REG_F16_32
	RISCV_REG_F16_64 = C.RISCV_REG_F16_64
	RISCV_REG_F17_32 = C.RISCV_REG_F17_32
	RISCV_REG_F17_64 = C.RISCV_REG_F17_64
	RISCV_REG_F18_32 = C.RISCV_REG_F18_32
	RISCV_REG_F18_64 = C.RISCV_REG_F18_64
	RISCV_REG_F19_32 = C.RISCV_REG_F19_32
	RISCV_REG_F19_64 = C.RISCV_REG_F19_64
	RISCV_REG_F20_32 = C.RISCV_REG_F20_32
	RISCV_REG_F20_64 = C.RISCV_REG_F20_64
	RISCV_REG_F21_32 = C.RISCV_REG_F21_32
	RISCV_REG_F21_64 = C.RISCV_REG_F21_64
	RISCV_REG_F22_32 = C.RISCV_REG_F22_32
	RISCV_REG_F22_64 = C.RISCV_REG_F22_64
	RISCV_REG_F23_32 = C.RISCV_REG_F23_32
	RISCV_REG_F23_64 = C.RISCV_REG_F23_64
	RISCV_REG_F24_32 = C.RISCV_REG_F24_32
	RISCV_REG_F24_64 = C.RISCV_REG_F24_64
	RISCV_REG_F25_32 = C.RISCV_REG_F25_32
	RISCV_REG_F25_64 = C.RISCV_REG_F25_64
	RISCV_REG_F26_32 = C.RISCV_REG_F26_32
	RISCV_REG_F26_64 = C.RISCV_REG_F26_64
	RISCV_REG_F27_32 = C.RISCV_REG_F27_32
	RISCV_REG_F27_64 = C.RISCV_REG_F27_64
	RISCV_REG_F28_32 = C.RISCV_REG_F28_32
	RISCV_REG_F28_64 = C.RISCV_REG_F28_64
	RISCV_REG_F29_32 = C.RISCV_REG_F29_32
	RISCV_REG_F29_64 = C.RISCV_REG_F29_64
	RISCV_REG_F30_32 = C.RISCV_REG_F30_32
	RISCV_REG_F30_64 = C.RISCV_REG_F30_64
	RISCV_REG_F31_32 = C.RISCV_REG_F31_32
	RISCV_REG_F31_64 = C.RISCV_REG_F31_64
)

var RiscVRegNameMap = map[uint]string{
	RISCV_REG_X0:     "RISCV_REG_X0(ZERO)",
	RISCV_REG_X1:     "RISCV_REG_X1(RA)",
	RISCV_REG_X2:     "RISCV_REG_X2(SP)",
	RISCV_REG_X3:     "RISCV_REG_X3(GP)",
	RISCV_REG_X4:     "RISCV_REG_X4(TP)",
	RISCV_REG_X5:     "RISCV_REG_X5(T0)",
	RISCV_REG_X6:     "RISCV_REG_X6(T1)",
	RISCV_REG_X7:     "RISCV_REG_X7(T2)",
	RISCV_REG_X8:     "RISCV_REG_X8(S0,FP)",
	RISCV_REG_X9:     "RISCV_REG_X9(S1)",
	RISCV_REG_X10:    "RISCV_REG_X10(A0)",
	RISCV_REG_X11:    "RISCV_REG_X11(A1)",
	RISCV_REG_X12:    "RISCV_REG_X12(A2)",
	RISCV_REG_X13:    "RISCV_REG_X13(A3)",
	RISCV_REG_X14:    "RISCV_REG_X14(A4)",
	RISCV_REG_X15:    "RISCV_REG_X15(A5)",
	RISCV_REG_X16:    "RISCV_REG_X16(A6)",
	RISCV_REG_X17:    "RISCV_REG_X17(A7)",
	RISCV_REG_X18:    "RISCV_REG_X18(S2)",
	RISCV_REG_X19:    "RISCV_REG_X19(S3)",
	RISCV_REG_X20:    "RISCV_REG_X20(S4)",
	RISCV_REG_X21:    "RISCV_REG_X21(S5)",
	RISCV_REG_X22:    "RISCV_REG_X22(S6)",
	RISCV_REG_X23:    "RISCV_REG_X23(S7)",
	RISCV_REG_X24:    "RISCV_REG_X24(S8)",
	RISCV_REG_X25:    "RISCV_REG_X25(S9)",
	RISCV_REG_X26:    "RISCV_REG_X26(S10)",
	RISCV_REG_X27:    "RISCV_REG_X27(S11)",
	RISCV_REG_X28:    "RISCV_REG_X28(T3)",
	RISCV_REG_X29:    "RISCV_REG_X29(T4)",
	RISCV_REG_X30:    "RISCV_REG_X30(T5)",
	RISCV_REG_X31:    "RISCV_REG_X31(T6)",
	RISCV_REG_F0_32:  "RISCV_REG_F0_32",
	RISCV_REG_F0_64:  "RISCV_REG_F0_64",
	RISCV_REG_F1_32:  "RISCV_REG_F1_32",
	RISCV_REG_F1_64:  "RISCV_REG_F1_64",
	RISCV_REG_F2_32:  "RISCV_REG_F2_32",
	RISCV_REG_F2_64:  "RISCV_REG_F2_64",
	RISCV_REG_F3_32:  "RISCV_REG_F3_32",
	RISCV_REG_F3_64:  "RISCV_REG_F3_64",
	RISCV_REG_F4_32:  "RISCV_REG_F4_32",
	RISCV_REG_F4_64:  "RISCV_REG_F4_64",
	RISCV_REG_F5_32:  "RISCV_REG_F5_32",
	RISCV_REG_F5_64:  "RISCV_REG_F5_64",
	RISCV_REG_F6_32:  "RISCV_REG_F6_32",
	RISCV_REG_F6_64:  "RISCV_REG_F6_64",
	RISCV_REG_F7_32:  "RISCV_REG_F7_32",
	RISCV_REG_F7_64:  "RISCV_REG_F7_64",
	RISCV_REG_F8_32:  "RISCV_REG_F8_32",
	RISCV_REG_F8_64:  "RISCV_REG_F8_64",
	RISCV_REG_F9_32:  "RISCV_REG_F9_32",
	RISCV_REG_F9_64:  "RISCV_REG_F9_64",
	RISCV_REG_F10_32: "RISCV_REG_F10_32",
	RISCV_REG_F10_64: "RISCV_REG_F10_64",
	RISCV_REG_F11_32: "RISCV_REG_F11_32",
	RISCV_REG_F11_64: "RISCV_REG_F11_64",
	RISCV_REG_F12_32: "RISCV_REG_F12_32",
	RISCV_REG_F12_64: "RISCV_REG_F12_64",
	RISCV_REG_F13_32: "RISCV_REG_F13_32",
	RISCV_REG_F13_64: "RISCV_REG_F13_64",
	RISCV_REG_F14_32: "RISCV_REG_F14_32",
	RISCV_REG_F14_64: "RISCV_REG_F14_64",
	RISCV_REG_F15_32: "RISCV_REG_F15_32",
	RISCV_REG_F15_64: "RISCV_REG_F15_64",
	RISCV_REG_F16_32: "RISCV_REG_F16_32",
	RISCV_REG_F16_64: "RISCV_REG_F16_64",
	RISCV_REG_F17_32: "RISCV_REG_F17_32",
	RISCV_REG_F17_64: "RISCV_REG_F17_64",
	RISCV_REG_F18_32: "RISCV_REG_F18_32",
	RISCV_REG_F18_64: "RISCV_REG_F18_64",
	RISCV_REG_F19_32: "RISCV_REG_F19_32",
	RISCV_REG_F19_64: "RISCV_REG_F19_64",
	RISCV_REG_F20_32: "RISCV_REG_F20_32",
	RISCV_REG_F20_64: "RISCV_REG_F20_64",
	RISCV_REG_F21_32: "RISCV_REG_F21_32",
	RISCV_REG_F21_64: "RISCV_REG_F21_64",
	RISCV_REG_F22_32: "RISCV_REG_F22_32",
	RISCV_REG_F22_64: "RISCV_REG_F22_64",
	RISCV_REG_F23_32: "RISCV_REG_F23_32",
	RISCV_REG_F23_64: "RISCV_REG_F23_64",
	RISCV_REG_F24_32: "RISCV_REG_F24_32",
	RISCV_REG_F24_64: "RISCV_REG_F24_64",
	RISCV_REG_F25_32: "RISCV_REG_F25_32",
	RISCV_REG_F25_64: "RISCV_REG_F25_64",
	RISCV_REG_F26_32: "RISCV_REG_F26_32",
	RISCV_REG_F26_64: "RISCV_REG_F26_64",
	RISCV_REG_F27_32: "RISCV_REG_F27_32",
	RISCV_REG_F27_64: "RISCV_REG_F27_64",
	RISCV_REG_F28_32: "RISCV_REG_F28_32",
	RISCV_REG_F28_64: "RISCV_REG_F28_64",
	RISCV_REG_F29_32: "RISCV_REG_F29_32",
	RISCV_REG_F29_64: "RISCV_REG_F29_64",
	RISCV_REG_F30_32: "RISCV_REG_F30_32",
	RISCV_REG_F30_64: "RISCV_REG_F30_64",
	RISCV_REG_F31_32: "RISCV_REG_F31_32",
	RISCV_REG_F31_64: "RISCV_REG_F31_64",
}

const (
	CS_OPT_INVALID          = C.CS_OPT_INVALID
	CS_OPT_SYNTAX           = C.CS_OPT_SYNTAX
	CS_OPT_DETAIL           = C.CS_OPT_DETAIL
	CS_OPT_MODE             = C.CS_OPT_MODE
	CS_OPT_MEM              = C.CS_OPT_MEM
	CS_OPT_SKIPDATA         = C.CS_OPT_SKIPDATA
	CS_OPT_SKIPDATA_SETUP   = C.CS_OPT_SKIPDATA_SETUP
	CS_OPT_MNEMONIC         = C.CS_OPT_MNEMONIC
	CS_OPT_UNSIGNED         = C.CS_OPT_UNSIGNED
	CS_OPT_NO_BRANCH_OFFSET = C.CS_OPT_NO_BRANCH_OFFSET
)

const (
	CS_OPT_OFF              = C.CS_OPT_OFF
	CS_OPT_ON               = C.CS_OPT_ON
	CS_OPT_SYNTAX_DEFAULT   = C.CS_OPT_SYNTAX_DEFAULT
	CS_OPT_SYNTAX_INTEL     = C.CS_OPT_SYNTAX_INTEL
	CS_OPT_SYNTAX_ATT       = C.CS_OPT_SYNTAX_ATT
	CS_OPT_SYNTAX_NOREGNAME = C.CS_OPT_SYNTAX_NOREGNAME
	CS_OPT_SYNTAX_MASM      = C.CS_OPT_SYNTAX_MASM
	CS_OPT_SYNTAX_MOTOROLA  = C.CS_OPT_SYNTAX_MOTOROLA
)

type Capstone struct {
	handle C.csh
	arch   int
	mode   int
}

// Information that exists for every Instruction, regardless of arch.
// Structure members here will be promoted, so every Instruction will have
// them available. Check the constants for each architecture for available
// Instruction groups etc.
type InstructionHeader struct {
	Id      uint   // Internal id for this instruction. Subject to change.
	Address uint   // Nominal address ($ip) of this instruction
	Size    uint   // Size of the instruction, in bytes
	Bytes   []byte // Raw Instruction bytes
	// Not available in diet mode ( capstone built with CAPSTONE_DIET=yes )
	Mnemonic string // Ascii text of instruction mnemonic
	OpStr    string // Ascii text of instruction operands - Syntax depends on CS_OPT_SYNTAX
	// Not available without the decomposer. BE CAREFUL! By default,
	// CS_OPT_DETAIL is set to CS_OPT_OFF so the result of accessing these
	// members is undefined.
	AllRegistersRead    []uint // List of implicit and explicit registers read by this instruction
	AllRegistersWritten []uint // List of implicit and explicit registers written by this instruction
	RegistersRead       []uint // List of implicit registers read by this instruction
	RegistersWritten    []uint // List of implicit registers written by this instruction
	Groups              []uint // List of *_GRP_* groups this instruction belongs to.
}

// arch specific information will be filled in for exactly one of the
// substructures. Eg, an Engine created with New(CS_ARCH_ARM, CS_MODE_ARM) will
// fill in only the Arm structure member.
type Instruction struct {
	InstructionHeader
	X86 *X86Instruction
	//Arm64 *Arm64Instruction
	//Arm   *ArmInstruction
	Riscv *RiscvInstruction
}

const (
	RISCV_OP_INVALID = C.RISCV_OP_INVALID
	RISCV_OP_REG     = C.RISCV_OP_REG
	RISCV_OP_IMM     = C.RISCV_OP_IMM
	RISCV_OP_MEM     = C.RISCV_OP_MEM
)

type RiscvMemoryOperand struct {
	Base uint
	Disp int64
}
type RiscvOperand struct {
	Type uint
	Reg  uint
	Imm  int64
	// access field is supported later 6.0.0
	// Access uint8
	Mem RiscvMemoryOperand
}

type RiscvInstruction struct {
	NeedEffectiveAddr bool
	OpCount           uint8
	Operands          []RiscvOperand
}
type X86Instruction struct {
	Prefix   []byte
	Opcode   []byte
	Rex      byte
	AddrSize byte
	ModRM    byte
	Sib      byte
	Disp     int64
	SibIndex uint
	SibScale int8
	SibBase  uint
	XopCC    uint
	SseCC    uint
	AvxCC    uint
	AvxSAE   bool
	AvxRM    uint
	EFlags   uint64
	FPUFlags uint64
	Operands []X86Operand
	Encoding X86Encoding
}

// Number of Operands of a given X86_OP_* type
func (insn X86Instruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type X86Encoding struct {
	ModRMOffset byte
	DispOffset  byte
	DispSize    byte
	ImmOffset   byte
	ImmSize     byte
}

type X86Operand struct {
	Type          uint // X86_OP_* - determines which field is set below
	Reg           uint
	Imm           int64
	Mem           X86MemoryOperand
	Size          uint8
	Access        uint8
	AvxBcast      uint
	AvxZeroOpmask bool
}

type X86MemoryOperand struct {
	Segment uint
	Base    uint
	Index   uint
	Scale   int
	Disp    int64
}

func fillRiscvHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_riscv := (*C.cs_riscv)(unsafe.Pointer(&raw.detail.anon0[0]))

	riscv := RiscvInstruction{
		NeedEffectiveAddr: bool(cs_riscv.need_effective_addr),
		OpCount:           byte(cs_riscv.op_count),
	}

	var ops []C.cs_riscv_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_riscv.operands[0]))
	oih.Len = int(cs_riscv.op_count)
	oih.Cap = int(cs_riscv.op_count)
	for _, cop := range ops {
		if cop._type == RISCV_OP_INVALID {
			break
		}
		gop := RiscvOperand{
			Type: uint(cop._type),
		}

		switch cop._type {
		case RISCV_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case RISCV_OP_IMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case RISCV_OP_MEM:
			cop_mem := (*C.riscv_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem.Base = uint(cop_mem.base)
			gop.Mem.Disp = int64(cop_mem.disp)
		}

		riscv.Operands = append(riscv.Operands, gop)
	}

	insn.Riscv = &riscv
}

func fillX86Header(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_x86 := (*C.cs_x86)(unsafe.Pointer(&raw.detail.anon0[0]))

	// copy the prefix array to a new []byte
	pref := make([]byte, 4)
	for i := 0; i < 4; i++ {
		pref[i] = byte(cs_x86.prefix[i])
	}

	// Same for the opcode array
	opc := make([]byte, 4)
	for i := 0; i < 4; i++ {
		opc[i] = byte(cs_x86.opcode[i])
	}

	x86 := X86Instruction{
		Prefix:   pref,
		Opcode:   opc,
		Rex:      byte(cs_x86.rex),
		AddrSize: byte(cs_x86.addr_size),
		ModRM:    byte(cs_x86.modrm),
		Sib:      byte(cs_x86.sib),
		Disp:     int64(cs_x86.disp),
		SibIndex: uint(cs_x86.sib_index),
		SibScale: int8(cs_x86.sib_scale),
		SibBase:  uint(cs_x86.sib_base),
		XopCC:    uint(cs_x86.xop_cc),
		SseCC:    uint(cs_x86.sse_cc),
		AvxCC:    uint(cs_x86.avx_cc),
		AvxSAE:   bool(cs_x86.avx_sae),
		AvxRM:    uint(cs_x86.avx_rm),
		Encoding: X86Encoding{
			ModRMOffset: byte(cs_x86.encoding.modrm_offset),
			DispOffset:  byte(cs_x86.encoding.disp_offset),
			DispSize:    byte(cs_x86.encoding.disp_size),
			ImmOffset:   byte(cs_x86.encoding.imm_offset),
			ImmSize:     byte(cs_x86.encoding.imm_size),
		},
	}

	// Handle eflags and fpu_flags union
	x86.EFlags = uint64(*(*C.uint64_t)(unsafe.Pointer(&cs_x86.anon0[0])))
	for _, group := range insn.Groups {
		if group == X86_GRP_FPU {
			x86.EFlags = 0
			x86.FPUFlags = uint64(*(*C.uint64_t)(unsafe.Pointer(&cs_x86.anon0[0])))
			break
		}
	}

	// Cast the op_info to a []C.cs_x86_op
	var ops []C.cs_x86_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_x86.operands[0]))
	oih.Len = int(cs_x86.op_count)
	oih.Cap = int(cs_x86.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == X86_OP_INVALID {
			break
		}

		gop := X86Operand{
			Type:          uint(cop._type),
			Size:          uint8(cop.size),
			Access:        uint8(cop.access),
			AvxBcast:      uint(cop.avx_bcast),
			AvxZeroOpmask: bool(cop.avx_zero_opmask),
		}

		switch cop._type {
		// fake a union by setting only the correct struct member
		case X86_OP_IMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case X86_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case X86_OP_MEM:
			cmop := (*C.x86_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = X86MemoryOperand{
				Segment: uint(cmop.segment),
				Base:    uint(cmop.base),
				Index:   uint(cmop.index),
				Scale:   int(cmop.scale),
				Disp:    int64(cmop.disp),
			}
		}

		x86.Operands = append(x86.Operands, gop)
	}

	insn.X86 = &x86
}

// Called by the arch specific decomposers
func fillGenericHeader(c *Capstone, raw C.cs_insn, insn *Instruction) {

	insn.Id = uint(raw.id)
	insn.Address = uint(raw.address)
	insn.Size = uint(raw.size)

	if !dietMode {
		insn.Mnemonic = C.GoString(&raw.mnemonic[0])
		insn.OpStr = C.GoString(&raw.op_str[0])
	}

	bslice := make([]byte, raw.size)
	for i := 0; i < int(raw.size); i++ {
		bslice[i] = byte(raw.bytes[i])
	}
	insn.Bytes = bslice

	if raw.detail != nil && !dietMode {
		for i := 0; i < int(raw.detail.regs_read_count); i++ {
			insn.RegistersRead = append(insn.RegistersRead, uint(raw.detail.regs_read[i]))
		}

		for i := 0; i < int(raw.detail.regs_write_count); i++ {
			insn.RegistersWritten = append(insn.RegistersWritten, uint(raw.detail.regs_write[i]))
		}

		for i := 0; i < int(raw.detail.groups_count); i++ {
			insn.Groups = append(insn.Groups, uint(raw.detail.groups[i]))
		}

		var regsRead C.cs_regs
		var regsReadCount C.uint8_t
		var regsWrite C.cs_regs
		var regsWriteCount C.uint8_t
		res := C.cs_regs_access(
			c.handle,
			&raw,
			&regsRead[0],
			&regsReadCount,
			&regsWrite[0],
			&regsWriteCount)

		if Errno(res) == ErrOK {
			for i := 0; i < int(regsReadCount); i++ {
				insn.AllRegistersRead = append(insn.AllRegistersRead, uint(regsRead[i]))
			}

			for i := 0; i < int(regsWriteCount); i++ {
				insn.AllRegistersWritten = append(insn.AllRegistersWritten, uint(regsWrite[i]))
			}
		}
	}
}

func decomposeRiscV(c *Capstone, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(c, raw, decomp)
		fillRiscvHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}

func decomposeX86(c *Capstone, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(c, raw, decomp)
		fillX86Header(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}

func decomposeGeneric(c *Capstone, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(c, raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}

func New(arch int, mode int) (*Capstone, error) {
	var handle C.csh
	ret := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if ret != C.CS_ERR_OK {
		return nil, fmt.Errorf("Failed to initialize Capstone")
	}
	return &Capstone{handle: handle, arch: arch, mode: mode}, nil
}

// Disassemble a []byte full of opcodes.
//   - address - Address of the first instruction in the given code buffer.
//   - count - Number of instructions to disassemble, 0 to disassemble the whole []byte
//
// Underlying C resources are automatically free'd by this function.
func (c *Capstone) Disasm(input []byte, address, count uint64) ([]Instruction, error) {

	var insn *C.cs_insn
	bptr := (*C.uint8_t)(unsafe.Pointer(&input[0]))
	disassembled := C.cs_disasm(
		c.handle,
		bptr,
		C.size_t(len(input)),
		C.uint64_t(address),
		C.size_t(count),
		&insn,
	)

	if disassembled > 0 {
		defer C.cs_free((*C.cs_insn)(unsafe.Pointer(insn)), C.size_t(disassembled))
		// Create a slice, and reflect its header
		var insns []C.cs_insn
		h := (*reflect.SliceHeader)(unsafe.Pointer(&insns))
		// Manually fill in the ptr, len and cap from the raw C data
		h.Data = uintptr(unsafe.Pointer(insn))
		h.Len = int(disassembled)
		h.Cap = int(disassembled)

		switch c.arch {
		case CS_ARCH_X86:
			return decomposeX86(c, insns), nil
		case CS_ARCH_RISCV:
			return decomposeRiscV(c, insns), nil
		default:
			return decomposeGeneric(c, insns), nil
		}
	}
	return []Instruction{}, c.Errno()
}

func (c *Capstone) Option(opt_type C.cs_opt_type, opt_value C.size_t) error {
	ret := C.cs_option(c.handle, opt_type, opt_value)
	if ret != C.CS_ERR_OK {
		return fmt.Errorf("Failed to cs_option")
	}

	return nil
}

func ReverseInsns(insns []Instruction) []Instruction {
	rev_insns := make([]Instruction, len(insns))
	copy(rev_insns, insns)
	for i, j := 0, len(rev_insns)-1; i < j; i, j = i+1, j-1 {
		rev_insns[i], rev_insns[j] = rev_insns[j], rev_insns[i]
	}
	return rev_insns
}

func GetRiscVOperandTypeName(operand_type uint) string {
	operand_type_name := "UNKOWN"
	switch operand_type {
	case RISCV_OP_REG:
		operand_type_name = "REG"
	case RISCV_OP_IMM:
		operand_type_name = "IMM"
	case RISCV_OP_MEM:
		operand_type_name = "MEM"
	}

	return operand_type_name
}

func GetRiscVRegName(reg uint) string {
	regName := "Unknown"
	if value, exists := RiscVRegNameMap[reg]; exists {
		regName = value
	}
	return regName
}
