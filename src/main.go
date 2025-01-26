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

const (
	CMP_EQ       = iota // ==
	CMP_NOT_EQ          // !=
	CMP_LT              // <
	CMP_LT_OR_EQ        // <=
	CMP_GT              // >
	CMP_GT_OR_EQ        // >=
)
const (
	OPERAND_TYPE_REG = iota
	OPERAND_TYPE_MEM
)
const (
	CMP_COND_TYPE_ARGS = iota
	CMP_COND_TYPE_FUNC
	CMP_COND_TYPE_IMM
)

type RiscVOperand struct {
	Type int
	Reg  RiscVReg
	Mem  RiscVMem
	Imm  RiscVImm
}

type RiscVImm struct {
	Val  int64
	UVal uint64
}

type RiscVReg struct {
	RegNum   uint
	RegName  string
	Value    int64
	HasValue bool
}

type RiscVMem struct {
	Reg    RiscVReg
	Offset int64
}

type CmpCondition struct {
	CmpType int
}

type BasicBlock struct {
	entryAddr  uint64
	from       []uint64
	nextBlocks []uint64
	branchInsn *capstone.Instruction
	insns      []capstone.Instruction
}

type BranchInsnInfo struct {
	IsBranch            bool
	isConditionalBranch bool
}

var branchInsnMap = map[string]BranchInsnInfo{
	"BNE": {IsBranch: true, isConditionalBranch: true},
}
var loadImmInsnMap = map[string]struct{}{
	"C.LI": {},
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

			basicBlks := make(map[uint64]BasicBlock)
			var curBasickBlk *BasicBlock
			for _, insn := range insns {
				le_bytes := reverse(insn.Bytes)
				logger.ShowAppMsg("0x%x:\t%X\t%s\t%s, OpCount:%d\n", insn.Address, le_bytes, insn.Mnemonic, insn.OpStr, insn.Riscv.OpCount)
				if curBasickBlk == nil {
					curBasickBlk = &BasicBlock{
						entryAddr:  uint64(insn.Address),
						from:       []uint64{},
						nextBlocks: []uint64{},
						branchInsn: nil,
						insns:      []capstone.Instruction{},
					}
				}
				curBasickBlk.insns = append(curBasickBlk.insns, insn)
				isBransh, _ := isBranchInsn(&insn)
				if isBransh {
					curBasickBlk.branchInsn = &insn
					jmpAddrs := getJmpAddrs(&insn)
					curBasickBlk.nextBlocks = append(curBasickBlk.nextBlocks, jmpAddrs...)
					basicBlks[curBasickBlk.entryAddr] = *curBasickBlk
					curBasickBlk = nil
				}
			}
			if curBasickBlk != nil {
				basicBlks[curBasickBlk.entryAddr] = *curBasickBlk
				curBasickBlk = nil
			}

			logger.ShowAppMsg("**** basic blocks count:[%d] ****\n", len(basicBlks))
			relatedOperands := make([]RiscVOperand, 0)
			for entryAddr, _ := range basicBlks {
				logger.ShowAppMsg("**** entryAddr: 0x%X\n", entryAddr)
				revInsns := capstone.ReverseInsns(insns)
				for _, insn := range revInsns {
					logger.ShowAppMsg("0x%x:\t %s\n", insn.Address, insn.Mnemonic)
					isBransh, _ := isBranchInsn(&insn)
					if isBransh {
						operand := insn.Riscv.Operands[0]
						reg0Num := operand.Reg
						reg0Name := capstone.GetRiscVRegName(operand.Reg)
						reg0 := RiscVReg{RegNum: operand.Reg, RegName: reg0Name, Value: 0, HasValue: false}

						operand = insn.Riscv.Operands[1]
						reg1Num := operand.Reg
						reg1Name := capstone.GetRiscVRegName(operand.Reg)
						reg1 := RiscVReg{RegNum: operand.Reg, RegName: reg0Name, Value: 0, HasValue: false}
						logger.ShowAppMsg("reg0:%s[%d], reg1:%s[%d]\n", reg0Name, reg0Num, reg1Name, reg1Num)

						relatedOperands = append(relatedOperands, RiscVOperand{Type: OPERAND_TYPE_REG, Reg: reg0})
						relatedOperands = append(relatedOperands, RiscVOperand{Type: OPERAND_TYPE_REG, Reg: reg1})
						continue
					}
					isLoadImm := isLoadImmInsn(&insn)
					if isLoadImm {
						reg := insn.Riscv.Operands[0]
						imm := insn.Riscv.Operands[1]
						//reg.Reg
						for i, relatedOperand := range relatedOperands {
							if relatedOperand.Type != OPERAND_TYPE_REG {
								continue
							}
							if relatedOperand.Reg.RegNum == reg.Reg {
								relatedOperands[i].Reg.HasValue = true
								relatedOperands[i].Reg.Value = imm.Imm
								logger.ShowAppMsg("related reg found: [%s][%d], Value:[%d]\n", relatedOperand.Reg.RegName, relatedOperand.Reg.RegNum, imm.Imm)
								break
							}
						}

					}
				}
			}
		}
	}
}

func isBranchInsn(insn *capstone.Instruction) (isBranch bool, isConditionalBranch bool) {
	isBranch = false
	isConditionalBranch = false
	nm := strings.ToUpper(insn.Mnemonic)
	branchInfo, exist := branchInsnMap[nm]
	if exist {
		isBranch = branchInfo.IsBranch
		isConditionalBranch = branchInfo.IsBranch
	}

	return isBranch, isConditionalBranch
}

func isLoadImmInsn(insn *capstone.Instruction) (isLoadImm bool) {
	nm := strings.ToUpper(insn.Mnemonic)
	_, isLoadImm = loadImmInsnMap[nm]
	return isLoadImm
}

func getJmpAddrs(insn *capstone.Instruction) []uint64 {
	var jmpAddrs []uint64
	nm := strings.ToUpper(insn.Mnemonic)
	jmpAddr := uint64(insn.Address) + uint64(len(insn.Bytes))
	jmpAddrs = append(jmpAddrs, jmpAddr)
	logger.DLog("*** Next insn addr:0x%X\n", jmpAddr)

	switch nm {
	case "BNE":
		op := insn.Riscv.Operands[2]
		//type_name := capstone.GetRiscVOperandTypeName(op.Type)
		jmpAddr = uint64(insn.Address) + uint64(op.Imm)
		//logger.DLog("BNE Type:%s, Imm:0x%02X, jmpAddr:%X\n", type_name, op.Imm, jmpAddr)
		jmpAddrs = append(jmpAddrs, jmpAddr)
	}
	return jmpAddrs
}
