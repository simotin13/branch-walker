package elf

import (
	binutil "branch-walker/binutil"
	logger "branch-walker/logger"
	"errors"
	"fmt"
	"os"
	"unsafe"
)

type Elf64_Half = uint16
type Elf64_Sword = int32
type Elf64_Word = uint32
type Elf64_Addr = uint64
type Elf64_Off = uint64
type Elf64_Xword = uint64
type Elf64_Sxword = int64
type Elf64_Section = uint16
type Elf64_Versym = Elf64_Half

type Elf32_Half = uint16
type Elf32_Word = uint32
type Elf32_Sword = int32
type Elf32_Addr = uint32
type Elf32_Off = uint32
type Elf32_Section = uint16
type Elf32_Xword = uint64
type Elf32_Sxword = int64

const (
	EI_NIDENT     = 16
	EI_CLASS      = 4
	EI_DATA       = 5
	EI_VERSION    = 6
	EI_OSABI      = 7
	EI_ABIVERSION = 8
)

// OSABI
const (
	ELFOSABI_NONE       = 0
	ELFOSABI_SYSV       = 0
	ELFOSABI_HPUX       = 1
	ELFOSABI_NETBSD     = 2
	ELFOSABI_GNU        = 3
	ELFOSABI_LINUX      = ELFOSABI_GNU
	ELFOSABI_SOLARIS    = 6
	ELFOSABI_AIX        = 7
	ELFOSABI_IRIX       = 8
	ELFOSABI_FREEBSD    = 9
	ELFOSABI_TRU64      = 10
	ELFOSABI_MODESTO    = 11
	ELFOSABI_OPENBSD    = 12
	ELFOSABI_ARM_AEABI  = 64
	ELFOSABI_ARM        = 97
	ELFOSABI_STANDALONE = 255
)

// class
const (
	ELFCLASS_OFFSET = 4
	ELFCLASSNONE    = 0
	ELFCLASS32      = 1
	ELFCLASS64      = 2
)

const (
	ELFDATANONE = 0
	ELFDATA2LSB = 1
	ELFDATA2MSB = 2
)

const (
	ET_NONE = 0
	ET_REL  = 1
	ET_EXEC = 2
	ET_DYN  = 3
	ET_CORE = 4
	ET_NUM  = 5
)

const (
	OFFSET_ELF32_E_IDENT     = 0
	OFFSET_ELF32_E_TYPE      = EI_NIDENT
	OFFSET_ELF32_E_MACHINE   = OFFSET_ELF32_E_TYPE + unsafe.Sizeof(Elf32_Half(0))
	OFFSET_ELF32_E_VERSION   = OFFSET_ELF32_E_MACHINE + unsafe.Sizeof(Elf32_Half(0))
	OFFSET_ELF32_E_ENTRY     = OFFSET_ELF32_E_VERSION + unsafe.Sizeof(Elf32_Word(0))
	OFFSET_ELF32_E_PHOFF     = OFFSET_ELF32_E_ENTRY + unsafe.Sizeof(Elf32_Addr(0))
	OFFSET_ELF32_E_SHOFF     = OFFSET_ELF32_E_PHOFF + unsafe.Sizeof(Elf32_Off(0))
	OFFSET_ELF32_E_FLAGS     = OFFSET_ELF32_E_SHOFF + unsafe.Sizeof(Elf32_Off(0))
	OFFSET_ELF32_E_EHSIZE    = OFFSET_ELF32_E_FLAGS + unsafe.Sizeof(Elf32_Word(0))
	OFFSET_ELF32_E_PHENTSIZE = OFFSET_ELF32_E_EHSIZE + unsafe.Sizeof(Elf32_Half(0))
	OFFSET_ELF32_E_PHNUM     = OFFSET_ELF32_E_PHENTSIZE + unsafe.Sizeof(Elf32_Half(0))
	OFFSET_ELF32_E_SHENTSIZE = OFFSET_ELF32_E_PHNUM + unsafe.Sizeof(Elf32_Half(0))
	OFFSET_ELF32_E_SHNUM     = OFFSET_ELF32_E_SHENTSIZE + unsafe.Sizeof(Elf32_Half(0))
	OFFSET_ELF32_E_SHSTRNDX  = OFFSET_ELF32_E_SHNUM + unsafe.Sizeof(Elf32_Half(0))
)

const (
	OFFSET_ELF64_E_IDENT     = 0
	OFFSET_ELF64_E_TYPE      = EI_NIDENT
	OFFSET_ELF64_E_MACHINE   = OFFSET_ELF64_E_TYPE + unsafe.Sizeof(Elf64_Half(0))
	OFFSET_ELF64_E_VERSION   = OFFSET_ELF64_E_MACHINE + unsafe.Sizeof(Elf64_Half(0))
	OFFSET_ELF64_E_ENTRY     = OFFSET_ELF64_E_VERSION + unsafe.Sizeof(Elf64_Word(0))
	OFFSET_ELF64_E_PHOFF     = OFFSET_ELF64_E_ENTRY + unsafe.Sizeof(Elf64_Addr(0))
	OFFSET_ELF64_E_SHOFF     = OFFSET_ELF64_E_PHOFF + unsafe.Sizeof(Elf64_Off(0))
	OFFSET_ELF64_E_FLAGS     = OFFSET_ELF64_E_SHOFF + unsafe.Sizeof(Elf64_Off(0))
	OFFSET_ELF64_E_EHSIZE    = OFFSET_ELF64_E_FLAGS + unsafe.Sizeof(Elf64_Word(0))
	OFFSET_ELF64_E_PHENTSIZE = OFFSET_ELF64_E_EHSIZE + unsafe.Sizeof(Elf64_Half(0))
	OFFSET_ELF64_E_PHNUM     = OFFSET_ELF64_E_PHENTSIZE + unsafe.Sizeof(Elf64_Half(0))
	OFFSET_ELF64_E_SHENTSIZE = OFFSET_ELF64_E_PHNUM + unsafe.Sizeof(Elf64_Half(0))
	OFFSET_ELF64_E_SHNUM     = OFFSET_ELF64_E_SHENTSIZE + unsafe.Sizeof(Elf64_Half(0))
	OFFSET_ELF64_E_SHSTRNDX  = OFFSET_ELF64_E_SHNUM + unsafe.Sizeof(Elf64_Half(0))
)

const (
	PT_NULL         = 0          // Program header table entry unused
	PT_LOAD         = 1          // Loadable program segment
	PT_DYNAMIC      = 2          // Dynamic linking information
	PT_INTERP       = 3          // Program interpreter
	PT_NOTE         = 4          // Auxiliary information
	PT_SHLIB        = 5          // Reserved
	PT_PHDR         = 6          // Entry for header table itself
	PT_TLS          = 7          // Thread-local storage segment
	PT_NUM          = 8          // Number of defined types
	PT_LOOS         = 0x60000000 // Start of OS-specific
	PT_GNU_EH_FRAME = 0x6474e550 // GCC .eh_frame_hdr segment
	PT_GNU_STACK    = 0x6474e551 // Indicates stack executability
	PT_GNU_RELRO    = 0x6474e552 // Read-only after relocation
)

// p_flags
const (
	PF_X = 0x01 // Segment is executable
	PF_W = 0x02 // Segment is writable
	PF_R = 0x04 // Segment is readable
)

const (
	SHT_NULL           = 0          // Section header table entry unused
	SHT_PROGBITS       = 1          // Program data
	SHT_SYMTAB         = 2          // Symbol table
	SHT_STRTAB         = 3          // String table
	SHT_RELA           = 4          // Relocation entries with addends
	SHT_HASH           = 5          // Symbol hash table
	SHT_DYNAMIC        = 6          // Dynamic linking information
	SHT_NOTE           = 7          // Notes
	SHT_NOBITS         = 8          // Program space with no data (bss)
	SHT_REL            = 9          // Relocation entries, no addends
	SHT_SHLIB          = 10         // Reserved
	SHT_DYNSYM         = 11         // Dynamic linker symbol table
	SHT_INIT_ARRAY     = 14         // Array of constructors
	SHT_FINI_ARRAY     = 15         // Array of destructors
	SHT_PREINIT_ARRAY  = 16         // Array of pre-constructors
	SHT_GROUP          = 17         // Section group
	SHT_SYMTAB_SHNDX   = 18         // Extended section indeces
	SHT_NUM            = 19         // Number of defined types.
	SHT_LOOS           = 0x60000000 // Start OS-specific.
	SHT_GNU_ATTRIBUTES = 0x6ffffff5 // Object attributes.
	SHT_GNU_HASH       = 0x6ffffff6 // GNU-style hash table.
	SHT_GNU_LIBLIST    = 0x6ffffff7 // Prelink library list
	SHT_CHECKSUM       = 0x6ffffff8 // Checksum for DSO content.
	SHT_LOSUNW         = 0x6ffffffa // Sun-specific low bound.
	SHT_SUNW_move      = 0x6ffffffa
	SHT_SUNW_COMDAT    = 0x6ffffffb
	SHT_SUNW_syminfo   = 0x6ffffffc
	SHT_GNU_verdef     = 0x6ffffffd // Version definition section.
	SHT_GNU_verneed    = 0x6ffffffe // Version needs section.
	SHT_GNU_versym     = 0x6fffffff // Version symbol table.
	SHT_HISUNW         = 0x6fffffff // Sun-specific high bound.
	SHT_HIOS           = 0x6fffffff // End OS-specific type
	SHT_LOPROC         = 0x70000000 // Start of processor-specific
	SHT_HIPROC         = 0x7fffffff // End of processor-specific
	SHT_LOUSER         = 0x80000000 // Start of application-specific
	SHT_HIUSER         = 0x8fffffff // End of application-specific
)

const (
	SHN_UNDEF     = 0x0000
	SHN_LORESERVE = 0xff00
	SHN_LOPROC    = 0xff00
	SHN_BEFORE    = 0xff00
	SHN_AFTER     = 0xff01
	SHN_HIPROC    = 0xff1f
	SHN_ABS       = 0xfff1
	SHN_COMMON    = 0xfff2
	SHN_HIRESERVE = 0xffff
)

const (
	DT_NULL            = 0  // Marks end of dynamic section
	DT_NEEDED          = 1  // Name of needed library
	DT_PLTRELSZ        = 2  // Size in bytes of PLT relocs
	DT_PLTGOT          = 3  // Processor defined value
	DT_HASH            = 4  // Address of symbol hash table
	DT_STRTAB          = 5  // Address of string table
	DT_SYMTAB          = 6  // Address of symbol table
	DT_RELA            = 7  // Address of Rela relocs
	DT_RELASZ          = 8  // Total size of Rela relocs
	DT_RELAENT         = 9  // Size of one Rela reloc
	DT_STRSZ           = 10 // Size of string table
	DT_SYMENT          = 11 // Size of one symbol table entry
	DT_INIT            = 12 // Address of init function
	DT_FINI            = 13 // Address of termination function
	DT_SONAME          = 14 // Name of shared object
	DT_RPATH           = 15 // Library search path (deprecated)
	DT_SYMBOLIC        = 16 // Start symbol search here
	DT_REL             = 17 // Address of Rel relocs
	DT_RELSZ           = 18 // Total size of Rel relocs
	DT_RELENT          = 19 // Size of one Rel reloc
	DT_PLTREL          = 20 // Type of reloc in PLT
	DT_DEBUG           = 21 // For debugging; unspecified
	DT_TEXTREL         = 22 // Reloc might modify .text
	DT_JMPREL          = 23 // Address of PLT relocs
	DT_BIND_NOW        = 24 // Process relocations of object
	DT_INIT_ARRAY      = 25 // Array with addresses of init fct
	DT_FINI_ARRAY      = 26 // Array with addresses of fini fct
	DT_INIT_ARRAYSZ    = 27 // Size in bytes of DT_INIT_ARRAY
	DT_FINI_ARRAYSZ    = 28 // Size in bytes of DT_FINI_ARRAY
	DT_RUNPATH         = 29 // Library search path
	DT_FLAGS           = 30 // Flags for the object being loaded
	DT_ENCODING        = 32 // Start of encoded range
	DT_PREINIT_ARRAY   = 32 // Array with addresses of preinit fc
	DT_PREINIT_ARRAYSZ = 33 // size in bytes of DT_PREINIT_ARRAY
	DT_SYMTAB_SHNDX    = 34 // Address of SYMTAB_SHNDX section
	DT_NUM             = 35 // Number used

	DT_VALRNGLO       = 0x6ffffd00
	DT_VERSYM         = 0x6ffffff0
	DT_GNU_PRELINKED  = 0x6ffffdf5 // Prelinking timestamp
	DT_GNU_CONFLICTSZ = 0x6ffffdf6 // Size of conflict section
	DT_GNU_LIBLISTSZ  = 0x6ffffdf7 // Size of library list
	DT_CHECKSUM       = 0x6ffffdf8
	DT_PLTPADSZ       = 0x6ffffdf9
	DT_MOVEENT        = 0x6ffffdfa
	DT_MOVESZ         = 0x6ffffdfb
	DT_FEATURE_1      = 0x6ffffdfc // Feature selection (DTF_*).
	DT_POSFLAG_1      = 0x6ffffdfd // Flags for DT_* entries, effecting the following DT_* entry.
	DT_SYMINSZ        = 0x6ffffdfe // Size of syminfo table (in bytes)
	DT_SYMINENT       = 0x6ffffdff // Entry size of syminfo
	DT_VALRNGHI       = 0x6ffffdff

	DT_ADDRRNGLO    = 0x6ffffe00
	DT_GNU_HASH     = 0x6ffffef5 // GNU-style hash table.
	DT_TLSDESC_PLT  = 0x6ffffef6
	DT_TLSDESC_GOT  = 0x6ffffef7
	DT_GNU_CONFLICT = 0x6ffffef8 // Start of conflict section
	DT_GNU_LIBLIST  = 0x6ffffef9 // Library list
	DT_CONFIG       = 0x6ffffefa // Configuration information.
	DT_DEPAUDIT     = 0x6ffffefb // Dependency auditing.
	DT_AUDIT        = 0x6ffffefc // Object auditing.
	DT_PLTPAD       = 0x6ffffefd // PLT padding.
	DT_MOVETAB      = 0x6ffffefe // Move table.
	DT_SYMINFO      = 0x6ffffeff // Syminfo table.
	DT_ADDRRNGHI    = 0x6ffffeff

	// These were chosen by Sun.
	DT_FLAGS_1    = 0x6ffffffb // State flags, see DF_1_* below.
	DT_VERDEF     = 0x6ffffffc // Address of version definition
	DT_VERDEFNUM  = 0x6ffffffd // Number of version definitions
	DT_VERNEED    = 0x6ffffffe // Address of table with needed
	DT_VERNEEDNUM = 0x6fffffff // Number of needed versions
)

// DT_FEATURE_1 value
const (
	DTF_1_PARINIT = 0x01
	DTF_1_CONFEXP = 0x02
)

// DT_FLAGS value
const (
	DF_ORIGIN     = 0x00000001 // Object may use DF_ORIGIN
	DF_SYMBOLIC   = 0x00000002 // Symbol resolutions starts here
	DF_TEXTREL    = 0x00000004 // Object contains text relocations
	DF_BIND_NOW   = 0x00000008 // No lazy binding for this object
	DF_STATIC_TLS = 0x00000010 // Module uses the static TLS model
)

const (
	MACHINE_ARCH_NONE        = uint16(0)
	MACHINE_ARCH_X86         = uint16(3)
	MACHINE_ARCH_ARM         = uint16(40)
	MACHINE_ARCH_AMD         = uint16(62)
	MACHINE_ARCH_RENESAS_RX  = uint16(73)
	MACHINE_ARCH_ARM_AARCH64 = uint16(183)
	MACHINE_ARCH_RISCV       = uint16(243)
)

var machinesMap = map[uint16]string{
	MACHINE_ARCH_NONE:        "No machine",
	MACHINE_ARCH_X86:         "Intel 80386",
	MACHINE_ARCH_ARM:         "ARM",
	MACHINE_ARCH_AMD:         "Advanced Micro Devices X86-64",
	MACHINE_ARCH_RENESAS_RX:  "Renesas RX",
	MACHINE_ARCH_ARM_AARCH64: "ARM AARCH64",
	MACHINE_ARCH_RISCV:       "RISC-V",
}

var osAbiMap = map[byte]string{
	ELFOSABI_NONE:       "UNIX - System V",
	ELFOSABI_HPUX:       "HP-UX",
	ELFOSABI_NETBSD:     "NetBSD",
	ELFOSABI_GNU:        "Object uses GNU ELF extensions(Linux)",
	ELFOSABI_SOLARIS:    "Sun Solaris.",
	ELFOSABI_AIX:        "IBM AIX.",
	ELFOSABI_IRIX:       "SGI Irix.",
	ELFOSABI_FREEBSD:    "FreeBSD.",
	ELFOSABI_TRU64:      "Compaq TRU64 UNIX",
	ELFOSABI_MODESTO:    "Novell Modesto",
	ELFOSABI_OPENBSD:    "OpenBSD.",
	ELFOSABI_ARM_AEABI:  "ARM EABI",
	ELFOSABI_ARM:        "ARM",
	ELFOSABI_STANDALONE: "Standalone (embedded) application",
}

type Elf32Ehdr struct {
	E_ident     []byte     // Magic number and other info
	E_type      Elf32_Half // Object file type
	E_machine   Elf32_Half // Architecture
	E_version   Elf32_Word // Object file version
	E_entry     Elf32_Addr // Entry point virtual address
	E_phoff     Elf32_Off  // Program header table file offset
	E_shoff     Elf32_Off  // Section header table file offset
	E_flags     Elf32_Word // Processor-specific flags
	E_ehsize    Elf32_Half // ELF header size in bytes
	E_phentsize Elf32_Half // Program header table entry size
	E_phnum     Elf32_Half // Program header table entry count
	E_shentsize Elf32_Half // Section header table entry size
	E_shnum     Elf32_Half // Section header table entry count
	E_shstrndx  Elf32_Half // Section header string table index
}

type Elf64Ehdr struct {
	E_ident     []byte     // Magic number and other info
	E_type      Elf64_Half // Object file type
	E_machine   Elf64_Half // Architecture
	E_version   Elf64_Word // Object file version
	E_entry     Elf64_Addr // Entry point virtual address
	E_phoff     Elf64_Off  // Program header table file offset
	E_shoff     Elf64_Off  // Section header table file offset
	E_flags     Elf64_Word // Processor-specific flags
	E_ehsize    Elf64_Half // ELF header size in bytes
	E_phentsize Elf64_Half // Program header table entry size
	E_phnum     Elf64_Half // Program header table entry count
	E_shentsize Elf64_Half // Section header table entry size
	E_shnum     Elf64_Half // Section header table entry count
	E_shstrndx  Elf64_Half // Section header string table index
}

type Elf32Phdr struct {
	P_type   Elf32_Word
	P_flags  Elf32_Word
	P_offset Elf32_Off
	P_vaddr  Elf32_Addr
	P_paddr  Elf32_Addr
	P_filesz Elf32_Word
	P_memsz  Elf32_Word
	P_align  Elf32_Word
}

type Elf64Phdr struct {
	P_type   Elf64_Word
	P_flags  Elf64_Word
	P_offset Elf64_Off
	P_vaddr  Elf64_Addr
	P_paddr  Elf64_Addr
	P_filesz Elf64_Xword
	P_memsz  Elf64_Xword
	P_align  Elf64_Xword
}

type Elf32_Shdr struct {
	Sh_name      Elf32_Word // Section name (string tbl index)
	Sh_type      Elf32_Word // Section type
	Sh_flags     Elf32_Word // Section flags
	Sh_addr      Elf32_Addr // Section virtual addr at execution
	Sh_offset    Elf32_Off  // Section file offset
	Sh_size      Elf32_Word // Section size in bytes
	Sh_link      Elf32_Word // Link to another section
	Sh_info      Elf32_Word // Additional section information
	Sh_addralign Elf32_Word // Section alignment
	Sh_entsize   Elf32_Word // Entry size if section holds table
}

type Elf64_Shdr struct {
	Sh_name      Elf64_Word  // Section name (string tbl index)
	Sh_type      Elf64_Word  // Section type
	Sh_flags     Elf64_Xword // Section flags
	Sh_addr      Elf64_Addr  // Section virtual addr at execution
	Sh_offset    Elf64_Off   // Section file offset
	Sh_size      Elf64_Xword // Section size in bytes
	Sh_link      Elf64_Word  // Link to another section
	Sh_info      Elf64_Word  // Additional section information
	Sh_addralign Elf64_Xword // Section alignment
	Sh_entsize   Elf64_Xword // Entry size if section holds table
}

type Elf32_Sym struct {
	St_name  Elf32_Word    // Symbol name (string tbl index)
	St_value Elf32_Addr    // Symbol value
	St_size  Elf32_Word    // Symbol size
	St_info  uint8         // Symbol type and binding
	St_other uint8         // Symbol visibility
	St_shndx Elf32_Section // Section index
}

type Elf64_Sym struct {
	St_name  Elf64_Word    // Symbol name (string tbl index)
	St_info  uint8         // Symbol type and binding
	St_other uint8         // Symbol visibility
	St_shndx Elf64_Section // Section index
	St_value Elf64_Addr    // Symbol value
	St_size  Elf64_Xword   // Symbol size
}

type Elf32_Dyn struct {
	D_tag Elf32_Sword // Dynamic entry type
	D_val Elf32_Word  // Integer value
	D_ptr Elf32_Addr  // Address value
}

type Elf64_Dyn struct {
	D_tag Elf64_Sxword // Dynamic entry type
	D_val Elf64_Xword  // Integer value
	D_ptr Elf64_Addr   // Address value
}

type ElfObject interface {
	GetMachineArch() uint16
	GetMachineArchName() string
	ShowElfHeaderInfo()
	GetSectionBinByName(name string) []byte
	HasSection(name string) bool
	GetFuncIdxByAddr(addr uint64) int
	GetFuncsInfos() []ElfFunctionInfo
	ReadDynamic(dynamic []byte) []string
	GetPath() string
	GetExecPhOffset() uint64
}

type Elf32Object struct {
	Path           string
	Bin            []byte
	Elf32Ehdr      Elf32Ehdr
	Phdrs          []Elf32Phdr
	Shdrs          []Elf32_Shdr
	SymTbl         []Elf32_Sym
	FuncsInfos     []ElfFunctionInfo
	AddrFuncIdxMap map[uint64]int
	SectionNameMap map[string]int
	secNameStr     []byte
	strtbl         []byte
	dynstr         []byte
}

type Elf64Object struct {
	Path           string
	Bin            []byte
	Elf64Ehdr      Elf64Ehdr
	Phdrs          []Elf64Phdr
	Shdrs          []Elf64_Shdr
	SymTbl         []Elf64_Sym
	FuncsInfos     []ElfFunctionInfo
	AddrFuncIdxMap map[uint64]int
	SectionNameMap map[string]int
	secNameStr     []byte
	strtbl         []byte
	dynstr         []byte
}

func getMachineName(e_machine uint16) string {
	machine := "Unknown e_machine:#{e_machine}"
	v, exist := machinesMap[e_machine]
	if exist {
		machine = v
	}
	return machine
}

func IsELFFile(path string) bool {
	buf := make([]byte, 4)
	f, err := os.Open(path)
	if err != nil {
		// TODO err
		return false
	}

	defer f.Close()

	_, err = f.Read(buf)
	if err != nil {
		// TODO err
		return false
	}

	if (buf[0] != 0x7F) || (buf[1] != 'E') || (buf[2] != 'L') || (buf[3] != 'F') {
		return false
	}

	return true
}

func LoadFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		// TODO err
		return err
	}

	buf := make([]byte, fi.Size())
	f, err := os.Open(path)
	if err != nil {
		// TODO err
		return err
	}
	_, err = f.Read(buf)
	if err != nil {
		// TODO err
		return err
	}

	if (buf[0] != 0x7F) || (buf[1] != 'E') || (buf[2] != 'L') || (buf[3] != 'F') {
		msg := fmt.Sprintf("%s is not ELF file", path)
		return errors.New(msg)
	}

	//elfh := readELFHeader(buf)
	return nil
}

func IsELF32(bytes []uint8) bool {
	return bytes[EI_CLASS] == ELFCLASS32
}
func IsELF64(bytes []uint8) bool {
	return bytes[EI_CLASS] == ELFCLASS64
}

func getOSABIName(e_osabi byte) string {
	osabi := "Unknown e_machine:#{e_machine}"
	v, exist := osAbiMap[e_osabi]
	if exist {
		osabi = v
	}
	return osabi
}

func NewElf32Ehdr(bin []byte) Elf32Ehdr {
	var elf32Ehdr = Elf32Ehdr{}
	elf32Ehdr.E_ident = bin[0:EI_NIDENT]
	elf32Ehdr.E_type, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF32_E_TYPE:])
	elf32Ehdr.E_machine, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF32_E_MACHINE:])
	elf32Ehdr.E_version, _ = binutil.FromLeToUInt32(bin[OFFSET_ELF32_E_VERSION:])
	elf32Ehdr.E_entry, _ = binutil.FromLeToUInt32(bin[OFFSET_ELF32_E_ENTRY:])
	elf32Ehdr.E_phoff, _ = binutil.FromLeToUInt32(bin[OFFSET_ELF32_E_PHOFF:])
	elf32Ehdr.E_shoff, _ = binutil.FromLeToUInt32(bin[OFFSET_ELF32_E_SHOFF:])
	elf32Ehdr.E_flags, _ = binutil.FromLeToUInt32(bin[OFFSET_ELF32_E_FLAGS:])
	elf32Ehdr.E_ehsize, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF32_E_EHSIZE:])
	elf32Ehdr.E_phentsize, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF32_E_PHENTSIZE:])
	elf32Ehdr.E_phnum, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF32_E_PHNUM:])
	elf32Ehdr.E_shentsize, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF32_E_SHENTSIZE:])
	elf32Ehdr.E_shnum, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF32_E_SHNUM:])
	elf32Ehdr.E_shstrndx, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF32_E_SHSTRNDX:])
	return elf32Ehdr
}

func (elfObj *Elf32Object) getElf32Functions() []ElfFunctionInfo {
	funcs := []ElfFunctionInfo{}
	for _, sym := range elfObj.SymTbl {
		if sym.St_info&0x0F == STT_FUNC {
			if isSpecialShndx(sym.St_shndx) {
				continue
			}

			f := ElfFunctionInfo{}
			f.Name = elfObj.GetStrFromStrTbl(sym.St_name)

			// TODO mask for arm thumb ins address
			f.Addr = uint64(sym.St_value) & 0xFFFFFFFFFFFFFFFE
			f.Size = uint64(sym.St_size)

			sh := elfObj.Shdrs[sym.St_shndx]
			f.SecName = elfObj.getSectionName(sh.Sh_name)
			f.LineAddrs = map[uint64]LineAddrInfo{}
			funcs = append(funcs, f)
		}
	}
	return funcs
}

func NewElf64Ehdr(bin []byte) Elf64Ehdr {
	var elf64Ehdr = Elf64Ehdr{}
	elf64Ehdr.E_ident = bin[0:EI_NIDENT]
	elf64Ehdr.E_type, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF64_E_TYPE:])
	elf64Ehdr.E_machine, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF64_E_MACHINE:])
	elf64Ehdr.E_version, _ = binutil.FromLeToUInt32(bin[OFFSET_ELF64_E_VERSION:])
	elf64Ehdr.E_entry, _ = binutil.FromLeToUInt64(bin[OFFSET_ELF64_E_ENTRY:])
	elf64Ehdr.E_phoff, _ = binutil.FromLeToUInt64(bin[OFFSET_ELF64_E_PHOFF:])
	elf64Ehdr.E_shoff, _ = binutil.FromLeToUInt64(bin[OFFSET_ELF64_E_SHOFF:])
	elf64Ehdr.E_flags, _ = binutil.FromLeToUInt32(bin[OFFSET_ELF64_E_FLAGS:])
	elf64Ehdr.E_ehsize, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF64_E_EHSIZE:])
	elf64Ehdr.E_phentsize, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF64_E_PHENTSIZE:])
	elf64Ehdr.E_phnum, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF64_E_PHNUM:])
	elf64Ehdr.E_shentsize, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF64_E_SHENTSIZE:])
	elf64Ehdr.E_shnum, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF64_E_SHNUM:])
	elf64Ehdr.E_shstrndx, _ = binutil.FromLeToUInt16(bin[OFFSET_ELF64_E_SHSTRNDX:])
	return elf64Ehdr
}

func (elf32Ehdr *Elf32Ehdr) GetProgramHeaders(bin []byte) []Elf32Phdr {
	var phdrs []Elf32Phdr
	var offset = elf32Ehdr.E_phoff
	for i := 0; i < int(elf32Ehdr.E_phnum); i++ {
		elf32Phdr := NewElf32Phdr(bin[offset:])
		phdrs = append(phdrs, elf32Phdr)
		offset += uint32(elf32Ehdr.E_phentsize)
	}
	return phdrs
}

func (elf64Ehdr *Elf64Ehdr) GetProgramHeaders(bin []byte) []Elf64Phdr {
	var phdrs []Elf64Phdr
	var offset = elf64Ehdr.E_phoff
	for i := 0; i < int(elf64Ehdr.E_phnum); i++ {
		elf64Phdr := NewElf64Phdr(bin[offset:])
		phdrs = append(phdrs, elf64Phdr)
		offset += uint64(elf64Ehdr.E_phentsize)
	}
	return phdrs
}
func (elfObj *Elf32Object) HasSection(name string) bool {
	_, exist := elfObj.SectionNameMap[name]
	return exist
}

func (elfObj *Elf32Object) GetFuncIdxByAddr(addr uint64) int {
	funcIdx, exist := elfObj.AddrFuncIdxMap[addr]
	if !exist {
		return -1
	}
	return funcIdx
}

func (elfObj Elf32Object) GetFuncsInfos() []ElfFunctionInfo {
	return elfObj.FuncsInfos
}

func (elfObj Elf64Object) GetFuncsInfos() []ElfFunctionInfo {
	return elfObj.FuncsInfos
}

func (elfObj Elf32Object) GetPath() string {
	return elfObj.Path
}

func (elfObj Elf64Object) GetPath() string {
	return elfObj.Path
}

func (elfObj Elf32Object) GetExecPhOffset() uint64 {
	execPh := elfObj.GetExecPh()
	return uint64(execPh.P_offset)
}
func (elfObj Elf32Object) GetMachineArch() uint16 {
	return elfObj.Elf32Ehdr.E_machine
}
func (elfObj Elf64Object) GetMachineArch() uint16 {
	return elfObj.Elf64Ehdr.E_machine
}

func (elfObj Elf32Object) GetMachineArchName() string {
	return getMachineName(elfObj.Elf32Ehdr.E_machine)
}
func (elfObj Elf64Object) GetMachineArchName() string {
	return getMachineName(elfObj.Elf64Ehdr.E_machine)
}

func (elfObj Elf32Object) ShowElfHeaderInfo() {
	elfObj.Elf32Ehdr.ShowElfHeaderInfo()
}
func (elfObj Elf64Object) ShowElfHeaderInfo() {
	elfObj.Elf64Ehdr.ShowElfHeaderInfo()
}

func (elfObj Elf32Object) GetSectionBinByName(name string) []byte {
	shIdx, exist := elfObj.SectionNameMap[name]
	if !exist {
		return nil
	}
	sh := elfObj.Shdrs[shIdx]
	endOffset := sh.Sh_offset + sh.Sh_size
	return elfObj.Bin[sh.Sh_offset:endOffset]
}

func (elfObj *Elf64Object) GetSectionBinByName(name string) []byte {
	shIdx, exist := elfObj.SectionNameMap[name]
	if !exist {
		return nil
	}
	sh := elfObj.Shdrs[shIdx]
	endOffset := sh.Sh_offset + sh.Sh_size
	return elfObj.Bin[sh.Sh_offset:endOffset]
}

func (elfObj Elf32Object) GetStrFromStrTbl(st_name Elf64_Word) string {
	str := ""
	offset := st_name
	for elfObj.strtbl[offset] != 0 {
		str += string(elfObj.strtbl[offset])
		offset++
	}
	return str
}

func (elfObj Elf32Object) ReadDynamic(dynamic []byte) []string {
	size := len(dynamic)
	offset := 0

	var dynlibs []string

	for offset < size {
		var dyn Elf32_Dyn
		// /var tag int32
		//var val uint64
		tag, _ := binutil.FromLeToInt32(dynamic[offset:])
		varSize := unsafe.Sizeof(Elf32_Sxword(0))
		offset += int(varSize)
		val, _ := binutil.FromLeToUInt32(dynamic[offset:])
		offset += 8
		dyn.D_tag = tag
		switch dyn.D_tag {
		case DT_NEEDED:
			libname := binutil.GetString(elfObj.dynstr, uint64(val))
			dyn.D_val = val
			dynlibs = append(dynlibs, libname)
			logger.TLog(libname)
		case DT_PLTRELSZ:
			// TODO must understand...
			dyn.D_val = val
		case DT_PLTGOT:
			// TODO must understand...
			dyn.D_ptr = val
		case DT_STRTAB:
			dyn.D_ptr = val
		case DT_SYMTAB:
			dyn.D_ptr = val
		case DT_RELA:
			dyn.D_ptr = val
		case DT_RELASZ:
			// TODO must understand...
			dyn.D_ptr = val
		case DT_RELAENT:
			// TODO must understand...
			dyn.D_ptr = val
		case DT_STRSZ:
			// size of strtab
			dyn.D_val = val
		case DT_SYMENT:
			// size of symtab
			dyn.D_val = val
		case DT_INIT:
			dyn.D_ptr = val
		case DT_FINI:
			dyn.D_ptr = val
		case DT_RELENT:
			// TODO must understand...
			dyn.D_val = val
		case DT_PLTREL:
			// TODO must understand...
			dyn.D_val = val
		case DT_DEBUG:
			// TODO what is this?
			dyn.D_val = val
		case DT_JMPREL:
			dyn.D_ptr = val
		case DT_INIT_ARRAY:
			dyn.D_ptr = val
		case DT_FINI_ARRAY:
			dyn.D_ptr = val
		case DT_INIT_ARRAYSZ:
			dyn.D_val = val
		case DT_FINI_ARRAYSZ:
			dyn.D_val = val
		case DT_RUNPATH:
			runpath := binutil.GetString(elfObj.dynstr, uint64(val))
			dyn.D_val = val
			logger.TLog(runpath)
			dyn.D_val = val
		case DT_FLAGS:
			// TODO
			switch val {
			case DF_ORIGIN:
				logger.TLog("DF_ORIGIN")
			case DF_SYMBOLIC:
				logger.TLog("DF_SYMBOLIC")
			case DF_TEXTREL:
				logger.TLog("DF_TEXTREL")
			case DF_BIND_NOW:
				logger.TLog("DF_BIND_NOW")
			case DF_STATIC_TLS:
				logger.TLog("DF_STATIC_TLS")
			default:
				panic("unexpected DT_FLAGS val")
			}
		case DT_VERSYM:
			dyn.D_val = val
			logger.TLog("DT_VERSYM 0x%x\n", val)
		case DT_FEATURE_1:
			dyn.D_val = val
			switch val {
			case DTF_1_PARINIT:
				// need initilize
			case DTF_1_CONFEXP:
				// need configuration file
			default:
				panic("Unexpected val")
			}
		case DT_GNU_HASH:
			dyn.D_val = val
			// TODO what is this ?
		case DT_FLAGS_1:
			dyn.D_val = val
			logger.TLog("DT_FLAGS_1 0x%x\n", val)
		case DT_VERDEFNUM:
			dyn.D_val = val
			logger.TLog("DT_VERDEFNUM 0x%x\n", val)
		case DT_VERNEED:
			dyn.D_ptr = val
			logger.TLog("DT_VERNEED 0x%x\n", val)
		case DT_VERNEEDNUM:
			dyn.D_val = val
			logger.TLog("DT_VERNEEDNUM 0x%x\n", val)
		default:
			// TODO not implemented.
		}
	}
	return dynlibs
}

func (elfObj Elf64Object) ReadDynamic(dynamic []byte) []string {
	size := len(dynamic)
	offset := 0

	var dynlibs []string

	for offset < size {
		var dyn Elf64_Dyn
		var tag int64
		var val uint64
		tag, _ = binutil.FromLeToInt64(dynamic[offset:])
		varSize := unsafe.Sizeof(Elf64_Sxword(0))
		offset += int(varSize)
		val, _ = binutil.FromLeToUInt64(dynamic[offset:])
		offset += 8
		dyn.D_tag = tag
		switch dyn.D_tag {
		case DT_NEEDED:
			libname := binutil.GetString(elfObj.dynstr, val)
			dyn.D_val = val
			dynlibs = append(dynlibs, libname)
			logger.TLog(libname)
		case DT_PLTRELSZ:
			// TODO must understand...
			dyn.D_val = val
		case DT_PLTGOT:
			// TODO must understand...
			dyn.D_ptr = val
		case DT_STRTAB:
			dyn.D_ptr = val
		case DT_SYMTAB:
			dyn.D_ptr = val
		case DT_RELA:
			dyn.D_ptr = val
		case DT_RELASZ:
			// TODO must understand...
			dyn.D_ptr = val
		case DT_RELAENT:
			// TODO must understand...
			dyn.D_ptr = val
		case DT_STRSZ:
			// size of strtab
			dyn.D_val = val
		case DT_SYMENT:
			// size of symtab
			dyn.D_val = val
		case DT_INIT:
			dyn.D_ptr = val
		case DT_FINI:
			dyn.D_ptr = val
		case DT_RELENT:
			// TODO must understand...
			dyn.D_val = val
		case DT_PLTREL:
			// TODO must understand...
			dyn.D_val = val
		case DT_DEBUG:
			// TODO what is this?
			dyn.D_val = val
		case DT_JMPREL:
			dyn.D_ptr = val
		case DT_INIT_ARRAY:
			dyn.D_ptr = val
		case DT_FINI_ARRAY:
			dyn.D_ptr = val
		case DT_INIT_ARRAYSZ:
			dyn.D_val = val
		case DT_FINI_ARRAYSZ:
			dyn.D_val = val
		case DT_RUNPATH:
			runpath := binutil.GetString(elfObj.dynstr, val)
			dyn.D_val = val
			logger.TLog(runpath)
			dyn.D_val = val
		case DT_FLAGS:
			// TODO
			switch val {
			case DF_ORIGIN:
				logger.TLog("DF_ORIGIN")
			case DF_SYMBOLIC:
				logger.TLog("DF_SYMBOLIC")
			case DF_TEXTREL:
				logger.TLog("DF_TEXTREL")
			case DF_BIND_NOW:
				logger.TLog("DF_BIND_NOW")
			case DF_STATIC_TLS:
				logger.TLog("DF_STATIC_TLS")
			default:
				panic("unexpected DT_FLAGS val")
			}
		case DT_VERSYM:
			dyn.D_val = val
			logger.TLog("DT_VERSYM 0x%x\n", val)
		case DT_FEATURE_1:
			dyn.D_val = val
			switch val {
			case DTF_1_PARINIT:
				// need initilize
			case DTF_1_CONFEXP:
				// need configuration file
			default:
				panic("Unexpected val")
			}
		case DT_GNU_HASH:
			dyn.D_val = val
			// TODO what is this ?
		case DT_FLAGS_1:
			dyn.D_val = val
			logger.TLog("DT_FLAGS_1 0x%x\n", val)
		case DT_VERDEFNUM:
			dyn.D_val = val
			logger.TLog("DT_VERDEFNUM 0x%x\n", val)
		case DT_VERNEED:
			dyn.D_ptr = val
			logger.TLog("DT_VERNEED 0x%x\n", val)
		case DT_VERNEEDNUM:
			dyn.D_val = val
			logger.TLog("DT_VERNEEDNUM 0x%x\n", val)
		default:
			// TODO not implemented.
		}
	}
	return dynlibs
}

func (elf32Ehdr *Elf32Ehdr) ShowElfHeaderInfo() {

	fmt.Println("ELF Header:")
	fmt.Print("  Magic:   ")
	for _, by := range elf32Ehdr.E_ident {
		fmt.Printf("%02x ", by)
	}
	fmt.Println("")

	class := ""
	switch elf32Ehdr.E_ident[EI_CLASS] {
	case ELFCLASSNONE:
		class = "ELF None"
	case ELFCLASS32:
		class = "ELF32"
	case ELFCLASS64:
		class = "ELF64"
	default:
		class = "Unknown"
	}
	fmt.Printf("  Class:%34s\n", class)

	d := elf32Ehdr.E_ident[EI_DATA]
	data := ""
	switch d {
	case ELFDATANONE:
		data = "Invalid data encoding"
	case ELFDATA2LSB:
		data = "2's complement, little endian"
	case ELFDATA2MSB:
		data = "2's complement, big endian"
	default:
		data = fmt.Sprintf("Unknown %02x", d)
	}
	fmt.Printf("  Data:%59s\n", data)
	fmt.Printf("  Version:%28d (current)\n", elf32Ehdr.E_ident[EI_VERSION])

	abi := getOSABIName(elf32Ehdr.E_ident[EI_OSABI])
	fmt.Printf("  OS/ABI:%43s\n", abi)
	fmt.Printf("  ABI Version:%24d\n", elf32Ehdr.E_ident[EI_ABIVERSION])

	ty := ""
	switch elf32Ehdr.E_type {
	case ET_NONE:
		ty = "None"
	case ET_REL:
		ty = "REL (Relocatable file)"
	case ET_EXEC:
		ty = "EXEC (Executable file)"
	case ET_DYN:
		ty = "DYN (Shared object file)"
	case ET_CORE:
		ty = "Core"
	default:
		ty = fmt.Sprintf("Unknown format %04x", elf32Ehdr.E_type)
	}
	fmt.Printf("  Type:%30s%s\n", "", ty)

	fmt.Printf("  Machine:%27s%s\n", "", getMachineName(elf32Ehdr.E_machine))
	fmt.Printf("  Version:%27s0x%x\n", "", elf32Ehdr.E_version)
	fmt.Printf("  Entry point address:%15s0x%x\n", "", elf32Ehdr.E_entry)
	fmt.Printf("  Start of program headers:%10s%d (bytes into file)\n", "", elf32Ehdr.E_phoff)
	fmt.Printf("  Start of section headers:%10s%d (bytes into file)\n", "", elf32Ehdr.E_shoff)
	fmt.Printf("  Flags:%29s0x%x\n", "", elf32Ehdr.E_flags)
	fmt.Printf("  Size of this header:%15s%d (bytes)\n", "", elf32Ehdr.E_ehsize)
	fmt.Printf("  Size of program headers:%11s%d (bytes)\n", "", elf32Ehdr.E_phentsize)
	fmt.Printf("  Number of program headers:%9s%d\n", "", elf32Ehdr.E_phnum)
	fmt.Printf("  Size of section headers:%11s%d (bytes)\n", "", elf32Ehdr.E_shentsize)
	fmt.Printf("  Number of section headers:%9s%d\n", "", elf32Ehdr.E_shnum)
	fmt.Printf("  Section header string table index:%1s%d\n", "", elf32Ehdr.E_shstrndx)
}

func (elf64Ehdr *Elf64Ehdr) ShowElfHeaderInfo() {

	fmt.Println("ELF Header:")
	fmt.Print("  Magic:   ")
	for _, by := range elf64Ehdr.E_ident {
		fmt.Printf("%02x ", by)
	}
	fmt.Println("")

	class := ""
	switch elf64Ehdr.E_ident[EI_CLASS] {
	case ELFCLASSNONE:
		class = "ELF None"
	case ELFCLASS32:
		class = "ELF32"
	case ELFCLASS64:
		class = "ELF64"
	default:
		class = "Unknown"
	}
	fmt.Printf("  Class:%34s\n", class)

	d := elf64Ehdr.E_ident[EI_DATA]
	data := ""
	switch d {
	case ELFDATANONE:
		data = "Invalid data encoding"
	case ELFDATA2LSB:
		data = "2's complement, little endian"
	case ELFDATA2MSB:
		data = "2's complement, big endian"
	default:
		data = fmt.Sprintf("Unknown %02x", d)
	}
	fmt.Printf("  Data:%59s\n", data)
	fmt.Printf("  Version:%28d (current)\n", elf64Ehdr.E_ident[EI_VERSION])

	abi := getOSABIName(elf64Ehdr.E_ident[EI_OSABI])
	fmt.Printf("  OS/ABI:%43s\n", abi)
	fmt.Printf("  ABI Version:%24d\n", elf64Ehdr.E_ident[EI_ABIVERSION])

	ty := ""
	switch elf64Ehdr.E_type {
	case ET_NONE:
		ty = "None"
	case ET_REL:
		ty = "REL (Relocatable file)"
	case ET_EXEC:
		ty = "EXEC (Executable file)"
	case ET_DYN:
		ty = "DYN (Shared object file)"
	case ET_CORE:
		ty = "Core"
	default:
		ty = fmt.Sprintf("Unknown format %04x", elf64Ehdr.E_type)
	}
	fmt.Printf("  Type:%30s%s\n", "", ty)

	fmt.Printf("  Machine:%27s%s\n", "", getMachineName(elf64Ehdr.E_machine))
	fmt.Printf("  Version:%27s0x%x\n", "", elf64Ehdr.E_version)
	fmt.Printf("  Entry point address:%15s0x%x\n", "", elf64Ehdr.E_entry)
	fmt.Printf("  Start of program headers:%10s%d (bytes into file)\n", "", elf64Ehdr.E_phoff)
	fmt.Printf("  Start of section headers:%10s%d (bytes into file)\n", "", elf64Ehdr.E_shoff)
	fmt.Printf("  Flags:%29s0x%x\n", "", elf64Ehdr.E_flags)
	fmt.Printf("  Size of this header:%15s%d (bytes)\n", "", elf64Ehdr.E_ehsize)
	fmt.Printf("  Size of program headers:%11s%d (bytes)\n", "", elf64Ehdr.E_phentsize)
	fmt.Printf("  Number of program headers:%9s%d\n", "", elf64Ehdr.E_phnum)
	fmt.Printf("  Size of section headers:%11s%d (bytes)\n", "", elf64Ehdr.E_shentsize)
	fmt.Printf("  Number of section headers:%9s%d\n", "", elf64Ehdr.E_shnum)
	fmt.Printf("  Section header string table index:%1s%d\n", "", elf64Ehdr.E_shstrndx)
}

func NewElf32Phdr(bin []byte) Elf32Phdr {
	var elf32Phdr = Elf32Phdr{}
	var offset uintptr = 0

	size := unsafe.Sizeof(Elf32_Word(0))
	elf32Phdr.P_type, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Phdr.P_flags, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Off(0))
	elf32Phdr.P_offset, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Addr(0))
	elf32Phdr.P_vaddr, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Addr(0))
	elf32Phdr.P_paddr, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Phdr.P_filesz, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Phdr.P_memsz, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Phdr.P_align, _ = binutil.FromLeToUInt32(bin[offset:])

	return elf32Phdr
}

func NewElf64Phdr(bin []byte) Elf64Phdr {
	var elf64Phdr = Elf64Phdr{}
	var offset uintptr = 0

	size := unsafe.Sizeof(Elf64_Word(0))
	elf64Phdr.P_type, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Word(0))
	elf64Phdr.P_flags, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Off(0))
	elf64Phdr.P_offset, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Addr(0))
	elf64Phdr.P_vaddr, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Addr(0))
	elf64Phdr.P_paddr, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Xword(0))
	elf64Phdr.P_filesz, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Xword(0))
	elf64Phdr.P_memsz, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Xword(0))
	elf64Phdr.P_align, _ = binutil.FromLeToUInt64(bin[offset:])

	return elf64Phdr
}

func NewElf32(path string, bin []byte) *Elf32Object {
	elfObj := Elf32Object{}
	ehdr := NewElf32Ehdr(bin)
	elfObj.Path = path
	elfObj.Bin = bin
	elfObj.Elf32Ehdr = ehdr
	elfObj.Shdrs = ehdr.GetSectionHeaders(bin)
	elfObj.Phdrs = ehdr.GetProgramHeaders(bin)
	elfObj.SectionNameMap = make(map[string]int)
	strSh := elfObj.Shdrs[ehdr.E_shstrndx]
	elfObj.secNameStr = bin[strSh.Sh_offset : uint32(strSh.Sh_offset)+strSh.Sh_size]
	for i, sh := range elfObj.Shdrs {
		name := elfObj.getSectionName(sh.Sh_name)
		elfObj.SectionNameMap[name] = i
	}

	symTblBin := elfObj.GetSectionBinByName(".symtab")
	elfObj.SymTbl = getElf32SymTbl(symTblBin)

	elfObj.strtbl = elfObj.GetSectionBinByName(".strtab")
	elfObj.dynstr = elfObj.GetSectionBinByName(".dynstr")

	elfObj.FuncsInfos = elfObj.getElf32Functions()
	elfObj.AddrFuncIdxMap = map[uint64]int{}
	for funcIdx, f := range elfObj.FuncsInfos {
		var offset uint64 = 0
		for offset < f.Size {
			funcAddr := f.Addr + offset
			offset++
			elfObj.AddrFuncIdxMap[funcAddr] = funcIdx
		}

	}

	return &elfObj
}

func NewElf64(path string, bin []byte) *Elf64Object {
	elfObj := Elf64Object{}
	ehdr := NewElf64Ehdr(bin)
	elfObj.Path = path
	elfObj.Bin = bin
	elfObj.Elf64Ehdr = ehdr
	elfObj.Shdrs = ehdr.GetSectionHeaders(bin)
	elfObj.Phdrs = ehdr.GetProgramHeaders(bin)
	elfObj.SectionNameMap = make(map[string]int)
	strSh := elfObj.Shdrs[ehdr.E_shstrndx]
	elfObj.secNameStr = bin[strSh.Sh_offset : strSh.Sh_offset+strSh.Sh_size]
	for i, sh := range elfObj.Shdrs {
		name := elfObj.getSectionName(sh.Sh_name)
		elfObj.SectionNameMap[name] = i
	}

	symTblBin := elfObj.GetSectionBinByName(".symtab")
	elfObj.SymTbl = getElf64SymTbl(symTblBin)

	elfObj.strtbl = elfObj.GetSectionBinByName(".strtab")
	elfObj.dynstr = elfObj.GetSectionBinByName(".dynstr")

	elfObj.FuncsInfos = elfObj.getElf64Functions()
	elfObj.AddrFuncIdxMap = map[uint64]int{}
	for funcIdx, f := range elfObj.FuncsInfos {
		var offset uint64 = 0
		for offset < f.Size {
			funcAddr := f.Addr + offset
			offset++
			elfObj.AddrFuncIdxMap[funcAddr] = funcIdx
		}

	}

	return &elfObj
}

func (elf32Ehdr *Elf32Ehdr) GetSectionHeaders(bin []byte) []Elf32_Shdr {
	var shTbl []Elf32_Shdr
	offset := elf32Ehdr.E_shoff
	for i := 0; i < int(elf32Ehdr.E_shnum); i++ {
		elfShdr := NewElf32Shdr(bin[offset:])
		shTbl = append(shTbl, elfShdr)
		offset += uint32(elf32Ehdr.E_shentsize)
	}
	return shTbl
}

func (elf32Ehdr *Elf32Ehdr) GetSectionNames(strSec []byte) []string {
	var sectionNames []string
	pos := 0
	size := len(strSec)
	str := ""
	for pos < size {
		if strSec[pos] == 0 {
			sectionNames = append(sectionNames, str)
			str = ""
		} else {
			str += string(strSec[pos])
		}
		pos++
	}
	return sectionNames
}

func (elfObj *Elf64Object) HasSection(name string) bool {
	_, exist := elfObj.SectionNameMap[name]
	return exist
}

func (elfObj *Elf64Object) GetFuncIdxByAddr(addr uint64) int {
	funcIdx, exist := elfObj.AddrFuncIdxMap[addr]
	if !exist {
		return -1
	}
	return funcIdx
}

func (elfObj Elf64Object) GetExecPhOffset() uint64 {
	execPh := elfObj.GetExecPh()
	return execPh.P_offset
}

func (elfObj Elf64Object) GetShByName(name string) *Elf64_Shdr {
	shIdx, exist := elfObj.SectionNameMap[name]
	if exist {
		return &elfObj.Shdrs[shIdx]
	}

	return nil
}

func (elfObj Elf64Object) GetStrFromStrTbl(st_name Elf64_Word) string {
	str := ""
	offset := st_name
	for elfObj.strtbl[offset] != 0 {
		str += string(elfObj.strtbl[offset])
		offset++
	}
	return str
}

func (elf64Ehdr *Elf64Ehdr) GetSectionHeaders(bin []byte) []Elf64_Shdr {
	var shTbl []Elf64_Shdr
	offset := elf64Ehdr.E_shoff
	for i := 0; i < int(elf64Ehdr.E_shnum); i++ {
		elfShdr := NewElf64Shdr(bin[offset:])
		shTbl = append(shTbl, elfShdr)
		offset += uint64(elf64Ehdr.E_shentsize)
	}
	return shTbl
}

func (elf64Ehdr *Elf64Ehdr) GetSectionNames(strSec []byte) []string {
	var sectionNames []string
	pos := 0
	size := len(strSec)
	str := ""
	for pos < size {
		if strSec[pos] == 0 {
			sectionNames = append(sectionNames, str)
			str = ""
		} else {
			str += string(strSec[pos])
		}
		pos++
	}
	return sectionNames
}
func (elfObj *Elf32Object) getSectionName(sh_name Elf32_Word) string {
	secName := ""
	pos := sh_name
	for {
		if (elfObj.secNameStr[pos]) == 0 {
			break
		}
		secName += string(elfObj.secNameStr[pos])
		pos++
	}
	return secName
}
func getElf32SymTbl(bin []byte) []Elf32_Sym {
	len := len(bin)
	var offset uintptr = 0

	symTbl := []Elf32_Sym{}
	for int(offset) < len {
		elf32Sym := NewElf32Sym(bin[offset:])
		offset += unsafe.Sizeof(elf32Sym)
		symTbl = append(symTbl, elf32Sym)
	}
	return symTbl
}

func NewElf32Shdr(bin []byte) Elf32_Shdr {
	var elf32Shdr = Elf32_Shdr{}
	var offset uintptr = 0

	size := unsafe.Sizeof(Elf32_Word(0))
	elf32Shdr.Sh_name, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Shdr.Sh_type, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Shdr.Sh_flags, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Addr(0))
	elf32Shdr.Sh_addr, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Addr(0))
	elf32Shdr.Sh_offset, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Xword(0))
	elf32Shdr.Sh_size, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Shdr.Sh_link, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Shdr.Sh_info, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Xword(0))
	elf32Shdr.Sh_addralign, _ = binutil.FromLeToUInt32(bin[offset:])

	size = unsafe.Sizeof(Elf32_Xword(0))
	elf32Shdr.Sh_entsize, _ = binutil.FromLeToUInt32(bin[offset:])

	return elf32Shdr
}

func NewElf64Shdr(bin []byte) Elf64_Shdr {
	var elf64Shdr = Elf64_Shdr{}
	var offset uintptr = 0

	size := unsafe.Sizeof(Elf64_Word(0))
	elf64Shdr.Sh_name, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Word(0))
	elf64Shdr.Sh_type, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Xword(0))
	elf64Shdr.Sh_flags, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Addr(0))
	elf64Shdr.Sh_addr, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Addr(0))
	elf64Shdr.Sh_offset, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Xword(0))
	elf64Shdr.Sh_size, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Word(0))
	elf64Shdr.Sh_link, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Word(0))
	elf64Shdr.Sh_info, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Xword(0))
	elf64Shdr.Sh_addralign, _ = binutil.FromLeToUInt64(bin[offset:])

	size = unsafe.Sizeof(Elf64_Xword(0))
	elf64Shdr.Sh_entsize, _ = binutil.FromLeToUInt64(bin[offset:])

	return elf64Shdr
}

func (elfObj *Elf32Object) GetExecPh() *Elf32Phdr {
	for _, phdr := range elfObj.Phdrs {
		if (phdr.P_type == PT_LOAD) && ((phdr.P_flags & PF_X) != 0) {
			return &phdr
		}
	}
	return nil
}

func (elfObj *Elf64Object) GetExecPh() *Elf64Phdr {
	for _, phdr := range elfObj.Phdrs {
		if (phdr.P_type == PT_LOAD) && ((phdr.P_flags & PF_X) != 0) {
			return &phdr
		}
	}
	return nil
}

const (
	STT_NOTYPE  = 0
	STT_OBJECT  = 1
	STT_FUNC    = 2
	STT_SECTION = 3
	STT_FILE    = 4
)

var symTypes [16]string = [16]string{
	"NOTYPE",
	"OBJECT",
	"FUNC",
	"SECTION",
	"FILE",
	"COMMON",
	"TLS",
	"DUMMY",
	"DUMMY",
	"DUMMY",
	"LOOS",
	"DUMMY",
	"HIOS",
	"LOPROC",
	"SPARC_REGISTER",
	"HIPROC"}

var specialShNdx = [9]uint16{
	SHN_UNDEF,
	SHN_LORESERVE,
	SHN_LOPROC,
	SHN_BEFORE,
	SHN_AFTER,
	SHN_HIPROC,
	SHN_ABS,
	SHN_COMMON,
	SHN_HIRESERVE}

func isSpecialShndx(shndx Elf64_Half) bool {
	for _, v := range specialShNdx {
		if shndx == v {
			return true
		}
	}
	return false
}

func getSymType(st_info uint8) string {
	idx := st_info & 0x0F
	return symTypes[idx]
}

func (elfObj *Elf64Object) ShowSymTbl() {
	var secName = ""
	for i, sym := range elfObj.SymTbl {
		str := elfObj.GetStrFromStrTbl(sym.St_name)
		symType := getSymType(sym.St_info)
		if !isSpecialShndx(sym.St_shndx) {
			secName = elfObj.getSectionName(elfObj.Shdrs[sym.St_shndx].Sh_name)
		}
		fmt.Printf("[%d]: %016x    %d %s %s %s\n", i, sym.St_value, sym.St_size, symType, secName, str)
	}
}

func (elfObj *Elf64Object) getSectionName(sh_name Elf64_Word) string {
	secName := ""
	pos := sh_name
	for {
		if (elfObj.secNameStr[pos]) == 0 {
			break
		}
		secName += string(elfObj.secNameStr[pos])
		pos++
	}
	return secName
}

func getElf64SymTbl(bin []byte) []Elf64_Sym {
	len := len(bin)
	var offset uintptr = 0

	symTbl := []Elf64_Sym{}
	for int(offset) < len {
		elf64Sym := NewElf64Sym(bin[offset:])
		offset += unsafe.Sizeof(elf64Sym)
		symTbl = append(symTbl, elf64Sym)
	}
	return symTbl
}

type LineAddrInfo struct {
	Line        uint64
	Addr        uint64
	IsStmt      bool
	SrcDirName  string
	SrcFileName string
}

type ElfFunctionInfo struct {
	Name        string
	SrcDirName  string
	SrcFileName string
	Addr        uint64
	Size        uint64
	SecName     string
	LineAddrs   map[uint64]LineAddrInfo
}

func NewElf32Sym(bin []byte) Elf32_Sym {
	elf32Sym := Elf32_Sym{}
	var offset uintptr = 0

	size := unsafe.Sizeof(Elf32_Word(0))
	elf32Sym.St_name, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Addr(0))
	elf32Sym.St_value, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf32_Word(0))
	elf32Sym.St_size, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(uint8(0))
	elf32Sym.St_info = bin[offset]
	offset += size

	size = unsafe.Sizeof(uint8(0))
	elf32Sym.St_other = bin[offset]
	offset += size

	elf32Sym.St_shndx, _ = binutil.FromLeToUInt16(bin[offset:])
	return elf32Sym
}

func NewElf64Sym(bin []byte) Elf64_Sym {
	elf64Sym := Elf64_Sym{}
	var offset uintptr = 0
	size := unsafe.Sizeof(Elf64_Word(0))
	elf64Sym.St_name, _ = binutil.FromLeToUInt32(bin[offset:])
	offset += size

	size = unsafe.Sizeof(uint8(0))

	elf64Sym.St_info = bin[offset]
	offset += size

	size = unsafe.Sizeof(uint8(0))
	elf64Sym.St_other = bin[offset]
	offset += size

	size = unsafe.Sizeof(Elf64_Half(0))
	elf64Sym.St_shndx, _ = binutil.FromLeToUInt16(bin[offset:])
	offset += size

	size = unsafe.Sizeof(Elf64_Addr(0))
	elf64Sym.St_value, _ = binutil.FromLeToUInt64(bin[offset:])
	offset += size

	elf64Sym.St_size, _ = binutil.FromLeToUInt64(bin[offset:])
	return elf64Sym
}

func (elfObj *Elf64Object) getElf64Functions() []ElfFunctionInfo {
	funcs := []ElfFunctionInfo{}
	for _, sym := range elfObj.SymTbl {
		if sym.St_info&0x0F == STT_FUNC {
			if isSpecialShndx(sym.St_shndx) {
				continue
			}

			f := ElfFunctionInfo{}
			f.Name = elfObj.GetStrFromStrTbl(sym.St_name)
			f.Addr = sym.St_value
			f.Size = sym.St_size

			sh := elfObj.Shdrs[sym.St_shndx]
			f.SecName = elfObj.getSectionName(sh.Sh_name)
			f.LineAddrs = map[uint64]LineAddrInfo{}
			funcs = append(funcs, f)
		}
	}
	return funcs
}
