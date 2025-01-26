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
	CMP_COND_TYPE_ARGS = iota
	CMP_COND_TYPE_FUNC
	CMP_COND_TYPE_IMM
)

const (
	LinkValueTypeImm = capstone.RISCV_OP_IMM
	LinkValueTypeMem = capstone.RISCV_OP_MEM
	LinkValueTypeReg = capstone.RISCV_OP_REG
	LinkValueTypeFunc
)

type RiscVFunc struct {
	FuncName string
	Addr     uint64
}

type RiscVOperand struct {
	Type int
	Reg  RiscVReg
	Mem  RiscVMem
	Imm  RiscVImm
}

type RiscVImm struct {
	Val int64
}

type RiscVMem struct {
	RegNum    uint
	Offset    int64
	Value     int64
	ValueType int
	HasValue  bool
	LinkReg   *RiscVReg
}

type RiscVReg struct {
	RegNum        uint
	RegName       string
	HasValue      bool
	LinkValueType int
	LinkValue     int64
	LinkMem       *RiscVMem
	LinkReg       *RiscVReg
	LinkFunc      *RiscVFunc
}

type CmpCondition struct {
	CmpType int
}

type BasicBlock struct {
	EntryAddr       uint64
	From            []uint64
	NextBlocks      []uint64
	BranchInsn      *capstone.Instruction
	Insns           []capstone.Instruction
	RelatedOperands []RiscVReg
}

type BranchInsnInfo struct {
	IsBranch            bool
	isConditionalBranch bool
}
type SliceInfo struct {
	BasicBlks map[uint64]BasicBlock
}

var fancCallInsnMap = map[string]struct{}{
	"C.JAL": {},
}

var branchInsnMap = map[string]BranchInsnInfo{
	"BNE": {IsBranch: true, isConditionalBranch: true},
}

var loadImmInsnMap = map[string]struct{}{
	"C.LI": {},
}
var storeInsnMap = map[string]struct{}{
	"SW": {},
}
var loadMemInsnMap = map[string]struct{}{
	"LW": {},
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
	if machineArch != elf.MACHINE_ARCH_RISCV {
		logger.ShowErrorMsg("%s is not RISC-V Program", targetPath)
		os.Exit(-1)
	}

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

	funcSliceMap := make(map[uint64]SliceInfo)
	funcInfos := targetObj.GetFuncsInfos()
	for _, elfFuncInfo := range funcInfos {
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
		insns, err := cs.Disasm(f_bin, elfFuncInfo.Addr, 0)
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
					EntryAddr:  uint64(insn.Address),
					From:       []uint64{},
					NextBlocks: []uint64{},
					BranchInsn: nil,
					Insns:      []capstone.Instruction{},
				}
			}
			curBasickBlk.Insns = append(curBasickBlk.Insns, insn)
			isBransh, _ := isBranchInsn(&insn)
			if isBransh {
				curBasickBlk.BranchInsn = &insn
				jmpAddrs := getJmpAddrs(&insn)
				curBasickBlk.NextBlocks = append(curBasickBlk.NextBlocks, jmpAddrs...)
				basicBlks[curBasickBlk.EntryAddr] = *curBasickBlk
				curBasickBlk = nil
			}
		}
		if curBasickBlk != nil {
			basicBlks[curBasickBlk.EntryAddr] = *curBasickBlk
			curBasickBlk = nil
		}

		for entryAddr, basicBlk := range basicBlks {
			relatedOperands := make([]RiscVReg, 0)
			logger.ShowAppMsg("**** entryAddr: 0x%X\n", entryAddr)
			revInsns := capstone.ReverseInsns(insns)
			for _, insn := range revInsns {
				le_bytes := reverse(insn.Bytes)
				logger.ShowAppMsg("0x%x:\t%X\t%s\t%s, OpCount:%d\n", insn.Address, le_bytes, insn.Mnemonic, insn.OpStr, insn.Riscv.OpCount)

				isBransh, _ := isBranchInsn(&insn)
				if isBransh {
					operand := insn.Riscv.Operands[0]
					reg0Num := operand.Reg
					reg0Name := capstone.GetRiscVRegName(operand.Reg)

					operand = insn.Riscv.Operands[1]
					reg1Num := operand.Reg
					reg1Name := capstone.GetRiscVRegName(operand.Reg)
					logger.ShowAppMsg("reg0:%s[%d], reg1:%s[%d]\n", reg0Name, reg0Num, reg1Name, reg1Num)
					relatedOperands = append(relatedOperands, RiscVReg{RegNum: reg0Num, RegName: reg0Name, HasValue: false})
					relatedOperands = append(relatedOperands, RiscVReg{RegNum: reg1Num, RegName: reg1Name, HasValue: false})
					continue
				}
				isLoadImm := isLoadImmInsn(&insn)
				if isLoadImm {
					reg := insn.Riscv.Operands[0]
					imm := insn.Riscv.Operands[1]
					for i, relatedOperand := range relatedOperands {
						if relatedOperand.RegNum == reg.Reg {
							relatedOperands[i].HasValue = true
							relatedOperands[i].LinkValueType = LinkValueTypeImm // capstone.RISCV_OP_IMM
							relatedOperands[i].LinkValue = imm.Imm
							logger.ShowAppMsg("LoadImm Related reg found: [%s][%d], Value:[%d]\n", relatedOperand.RegName, relatedOperand.RegNum, imm.Imm)
							break
						}
						// update Link Value
						if !relatedOperand.HasValue {
							continue
						}
						if relatedOperand.LinkValueType != LinkValueTypeMem {
							continue
						}
						if !relatedOperand.LinkMem.HasValue {
							continue
						}
						if relatedOperand.LinkMem.ValueType != capstone.RISCV_OP_REG {
							continue
						}
						// update LinkMem Value Reg → Imm
						relatedOperands[i].LinkMem.ValueType = capstone.RISCV_OP_IMM
						relatedOperands[i].LinkMem.Value = imm.Imm
						regName := capstone.GetRiscVRegName(relatedOperands[i].LinkMem.RegNum)
						offset := relatedOperands[i].LinkMem.Offset
						value := relatedOperands[i].LinkMem.Value
						logger.ShowAppMsg("Update LinkMem to Imm: [%s][%d], Value:[%d]\n", regName, offset, value)
					}
					continue
				}
				isLoadMem := isLoadMemInsn(&insn)
				if isLoadMem {
					for i, relatedOperand := range relatedOperands {
						logger.ShowAppMsg("relatedOperand [%d],[%s]\n", i, relatedOperand.RegName)
						reg := insn.Riscv.Operands[0]
						mem := insn.Riscv.Operands[1]
						if relatedOperand.RegNum == reg.Reg {
							relatedOperands[i].HasValue = true
							relatedOperands[i].LinkValueType = LinkValueTypeMem
							relatedOperands[i].LinkMem = &RiscVMem{RegNum: mem.Mem.Base, Offset: mem.Mem.Disp, Value: 0, HasValue: false}
							regName := capstone.GetRiscVRegName(relatedOperands[i].LinkMem.RegNum)
							logger.ShowAppMsg("Load Related Reg found: [%s][%d], LinkMem:[%s][%d]\n", relatedOperand.RegName, relatedOperand.RegNum, regName, relatedOperands[i].LinkMem.RegNum)
						}
					}
					continue
				}
				isStore := isStoreInsn(&insn)
				if isStore {
					for i, relatedOperand := range relatedOperands {
						op0 := insn.Riscv.Operands[0]
						op1 := insn.Riscv.Operands[1]
						if !relatedOperand.HasValue {
							continue
						}
						if relatedOperand.LinkValueType == LinkValueTypeMem {
							// Update LinkMem to Reg
							isSameBase := relatedOperand.LinkMem.RegNum == op1.Mem.Base
							isSameOffset := uint(relatedOperand.LinkMem.Offset) == uint(op1.Mem.Disp)
							if isSameBase && isSameOffset {
								relatedOperands[i].LinkValueType = LinkValueTypeReg
								relatedOperands[i].LinkMem = nil
								regName := capstone.GetRiscVRegName(op0.Reg)
								relatedOperands[i].LinkReg = &RiscVReg{RegNum: op0.Reg, RegName: regName, HasValue: false}
							}
						}
					}
				}
				isFuncCall := isFuncCallInsn(&insn)
				if isFuncCall {
					for i, relatedOperand := range relatedOperands {
						if !relatedOperand.HasValue {
							continue
						}

						// TODO not only a0, need to check memory
						if relatedOperand.LinkValueType != LinkValueTypeReg {
							continue
						}
						// update LinkReg → Func
						//getFuncInfo
						relatedOperands[i].LinkReg = nil
						relatedOperands[i].LinkValueType = LinkValueTypeFunc
						relatedOperands[i].LinkFunc = &RiscVFunc{FuncName: "", Addr: 0}
					}
				}
			}
			basicBlk.RelatedOperands = relatedOperands
			basicBlks[entryAddr] = basicBlk
		}
		slice := SliceInfo{BasicBlks: basicBlks}
		funcSliceMap[elfFuncInfo.Addr] = slice
	}
}

func isFuncCallInsn(insn *capstone.Instruction) (isFuncCall bool) {
	nm := strings.ToUpper(insn.Mnemonic)
	_, isFuncCall = fancCallInsnMap[nm]
	return isFuncCall

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

func isStoreInsn(insn *capstone.Instruction) (isStore bool) {
	nm := strings.ToUpper(insn.Mnemonic)
	_, isStore = storeInsnMap[nm]
	return isStore
}

func isLoadMemInsn(insn *capstone.Instruction) (isLoadMem bool) {
	nm := strings.ToUpper(insn.Mnemonic)
	_, isLoadMem = loadMemInsnMap[nm]
	return isLoadMem

}
func getJmpAddrs(insn *capstone.Instruction) []uint64 {
	var jmpAddrs []uint64
	nm := strings.ToUpper(insn.Mnemonic)
	jmpAddr := uint64(insn.Address) + uint64(len(insn.Bytes))
	jmpAddrs = append(jmpAddrs, jmpAddr)
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
