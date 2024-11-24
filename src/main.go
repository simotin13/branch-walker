package main

import (
	capstone "branch-walker/capstone"
	elf "branch-walker/elf"
	logger "branch-walker/logger"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type RiscVImm struct {
	Val  int64
	UVal uint64
}

type RiscVReg struct {
	RegNum  uint
	RegName string
}
type RiscVMem struct {
	BaseReg     uint
	BaseRegName string
	Offset      int64
}

const (
	CMP_EQ       = iota // ==
	CMP_NOT_EQ          // !=
	CMP_LT              // <
	CMP_LT_OR_EQ        // <=
	CMP_GT              // >
	CMP_GT_OR_EQ        // >=
)

type CmpConstraint struct {
	CmpType int
}

type RiscVOperandInfo struct {
	Type uint
	Reg  RiscVReg
	Mem  RiscVMem
}

type SliceInfo struct {
	CmpInsn  capstone.Instruction
	Operands []RiscVOperandInfo
	Slices   []capstone.Instruction
}

type BasicBlock struct {
	entryAddr  uint64
	branchInsn capstone.Instruction
	nextBlocks []*BasicBlock
}

const (
	SLICING_STATUS_NONE = iota
	SLICING_STATUS_SLICING
)

var branchInsnMap = map[string]struct{}{
	"BNE": {},
}

var modifyInsnMap = map[string]struct{}{
	"ADDI": {}, // add immediate
	"SB":   {}, // store word
	"SH":   {}, // store half word
	"SW":   {}, // store word
	"LI":   {}, // load immediate
	"LUI":  {}, // load upper immediate
}

func reverse(data []byte) []byte {
	reversed := make([]byte, len(data))
	copy(reversed, data)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return reversed
}

func main() {
	logger.Setup("branch-walker", logger.TRACE, false)
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <target module>\n", os.Args[0])
		os.Exit(-1)
	}

	targetPath, err := filepath.Abs(os.Args[1])
	if err != nil {
		logger.ShowErrorMsg("%s\n", err.Error())
		os.Exit(-1)
	}

	// check target module is exist
	fi, err := os.Stat(targetPath)
	if err != nil {
		logger.ShowErrorMsg("%s cannot open\n", targetPath)
		os.Exit(-1)
	}

	// check target module is ELF Object
	if !elf.IsELFFile(targetPath) {
		logger.ShowErrorMsg("%s is not ELF Object File\n", targetPath)
		os.Exit(-1)
	}

	f, err := os.Open(targetPath)
	if err != nil {
		logger.ShowErrorMsg("%s cannot open", targetPath)
		os.Exit(-1)
	}
	defer f.Close()

	bin := make([]byte, fi.Size())
	f.Read(bin)

	var targetObj elf.ElfObject
	if elf.IsELF32(bin) {
		targetObj = elf.NewElf32(targetPath, bin)
	} else if elf.IsELF64(bin) {
		targetObj = elf.NewElf64(targetPath, bin)
	}
	machineArch := targetObj.GetMachineArch()
	machinearchName := targetObj.GetMachineArchName()

	logger.ShowAppMsg("Machine Arch: %s(0x%X)\n", machinearchName, machineArch)
	if machineArch == elf.MACHINE_ARCH_RISCV {
		cs, err := capstone.New(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCVC)
		if err != nil {
			logger.ShowErrorMsg("Failed to initialize capstone\n")
			os.Exit(-1)
		}

		err = cs.Option(capstone.CS_OPT_DETAIL, capstone.CS_OPT_ON)
		if err != nil {
			logger.ShowErrorMsg("Failed to cs_option\n")
			os.Exit(-1)
		}

		funcInfos := targetObj.GetFuncsInfos()
		for _, elfFuncInfo := range funcInfos {
			if elfFuncInfo.Name != "main" {
				continue
			}
			load_addr, err := targetObj.GetSectionLoadAddrByName(elfFuncInfo.SecName)
			if err != nil {
				logger.ShowErrorMsg("Failed to disassemble\n")
				os.Exit(-1)
			}

			fStart := elfFuncInfo.Addr - load_addr
			fEnd := fStart + elfFuncInfo.Size
			logger.DLog("Disassemble Name:%s, Addr:0x%X, Offset:0x%X, Size:%d, SecName:%s, LoadAddr:0x%X\n", elfFuncInfo.Name, elfFuncInfo.Addr, fStart, elfFuncInfo.Size, elfFuncInfo.SecName, load_addr)
			secBin := targetObj.GetSectionBinByName(elfFuncInfo.SecName)
			if secBin == nil {
				logger.ShowErrorMsg("Cannot find .text section\n")
				os.Exit(-1)
			}
			if elfFuncInfo.Size < 1 {
				logger.DLog("func '%s' size is 0\n", elfFuncInfo.Name)
				continue
			}
			f_bin := secBin[fStart:fEnd]
			insns, err := cs.Disasm(f_bin, fStart, 0)
			if err != nil {
				logger.ShowErrorMsg("Failed to disassemble\n")
				os.Exit(-1)
			}

			sliceInfo := SliceInfo{}
			basicBlock := BasicBlock{}
			slicingStatus := SLICING_STATUS_NONE
			rev_insns := capstone.ReverseInsns(insns)
			for _, insn := range rev_insns {
				le_bytes := reverse(insn.Bytes)
				logger.ShowAppMsg("0x%x:\t%X\t%s\t%s, OpCount:%d\n", insn.Address, le_bytes, insn.Mnemonic, insn.OpStr, insn.Riscv.OpCount)
				for i, op := range insn.Riscv.Operands {
					type_name := capstone.GetRiscVOperandTypeName(op.Type)
					switch op.Type {
					case capstone.RISCV_OP_REG:
						reg_name := capstone.GetRiscVRegName(op.Reg)
						logger.ShowAppMsg("        Operand:%d, Type:%s, Reg:%s\n", i, type_name, reg_name)
					case capstone.RISCV_OP_IMM:
						logger.ShowAppMsg("        Operand:%d, Type:%s, Imm:%d\n", i, type_name, op.Imm)
					case capstone.RISCV_OP_MEM:
						reg_name := capstone.GetRiscVRegName(op.Mem.Base)
						logger.ShowAppMsg("        Operand:%d, Type:%s, Base:%s, Disp:%d\n", i, type_name, reg_name, op.Mem.Disp)
					}
				}
				switch slicingStatus {
				case SLICING_STATUS_NONE:
					if isBranchInsn(&insn) {
						logger.DLog("Branch: %s\n", insn.Mnemonic)
						basicBlock.branchInsn = insn
						slicingStatus = SLICING_STATUS_SLICING
						sliceInfo.CmpInsn = insn
						for _, op := range insn.Riscv.Operands {
							switch op.Type {
							case capstone.RISCV_OP_REG:
								regName := capstone.GetRiscVRegName(op.Reg)
								regInfo := RiscVReg{RegNum: op.Reg, RegName: regName}
								operandInfo := RiscVOperandInfo{Type: op.Type, Reg: regInfo}
								sliceInfo.Operands = append(sliceInfo.Operands, operandInfo)
							case capstone.RISCV_OP_IMM:
								continue
							case capstone.RISCV_OP_MEM:
								regName := capstone.GetRiscVRegName(op.Reg)
								memInfo := RiscVMem{BaseReg: op.Reg, BaseRegName: regName, Offset: op.Mem.Disp}
								operandInfo := RiscVOperandInfo{Type: op.Type, Mem: memInfo}
								sliceInfo.Operands = append(sliceInfo.Operands, operandInfo)
								continue
							}
						}
					}
				case SLICING_STATUS_SLICING:
					// cmp 命令に使われているオペランドと同じメモリ、レジスタが更新されている命令をスライス
					check_slice(&insn, &sliceInfo)
				}
			}
		}
	}
}

func isBranchInsn(insn *capstone.Instruction) bool {
	nm := strings.ToUpper(insn.Mnemonic)
	_, found := branchInsnMap[nm]
	return found
}

func is_modify_insn(insn *capstone.Instruction) bool {
	nm := strings.ToUpper(insn.Mnemonic)
	_, found := modifyInsnMap[nm]
	return found
}
func check_slice(insn *capstone.Instruction, sliceInfo *SliceInfo) {
	nm := strings.ToUpper(insn.Mnemonic)
	for _, op := range sliceInfo.Operands {
		if op.Type == capstone.RISCV_OP_REG {
			switch nm {
			case "ADDI": // add immediate
				op0 := insn.Riscv.Operands[0]
				if op0.Reg == op.Reg.RegNum {
					sliceInfo.Slices = append(sliceInfo.Slices, *insn)
				}
				break
			case "SB": // store word
				break
			case "SH": // store half word
				break
			case "SW": // store word
				break
			case "LI": // load immediate
				break
			case "LUI": // load upper immediate
				break
			}
		}

	}
}
