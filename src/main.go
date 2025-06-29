package main

import (
	capstone "branch-walker/capstone"
	"branch-walker/dwarf"

	//	dwarf "branch-walker/dwarf"
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
	LinkValueTypeNone = 0
	LinkValueTypeReg  = capstone.RISCV_OP_REG
	LinkValueTypeImm  = capstone.RISCV_OP_IMM
	LinkValueTypeMem  = capstone.RISCV_OP_MEM
	LinkValueTypeEval = 0x10
	LinkValueTypeFunc = LinkValueTypeEval + 1
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
	LinkFunc      *RiscVFunc
	LinkExpress   *Expression
}

type RiscVArg struct {
	RegNum      uint
	RegName     string
	FrameOffset int64
	ArgType     int
}

// TODO コンテキストを用意して計算すべきか？
func (reg *RiscVReg) Eval() {
	for {
		if !reg.HasValue {
			break
		}
		switch reg.LinkValueType {
		case LinkValueTypeImm:
		case LinkValueTypeMem:
		case LinkValueTypeReg:
		case LinkValueTypeEval:
		case LinkValueTypeFunc:
		default:
		}
	}
}

type Expression struct {
	DstReg   RiscVReg
	Ins      string
	operands []RiscVOperand
}

func (exp *Expression) Eval() {
	switch exp.Ins {
	case "+":
		//op0 := exp.operands[0]
		//op1 := exp.operands[1]

	case "-":
	case "*":
	case "/":
	case "&":
	case "|":
	case "^":
	case "<<":
	case ">>":
	case "%":
	default:

	}
}

type RiscVContext struct {
	Regs [32]RiscVReg
	Mem  map[uint64]uint8
}

type CmpCondition struct {
	CmpType int
}

type BasicBlock struct {
	EntryAddr       uint64
	From            []uint64
	NextAddrs       []uint64
	BranchInsn      *capstone.Instruction
	Insns           []capstone.Instruction
	RelatedOperands []RiscVReg
}

type BranchInsnInfo struct {
	IsBranch            bool
	IsConditionalBranch bool
}
type FuncSlice struct {
	Name      string
	Addr      uint64
	Args      []RiscVArg
	BasicBlks map[uint64]BasicBlock
}

var mvInsnMap = map[string]struct{}{
	"C.MV": {},
}
var fancCallInsnMap = map[string]struct{}{
	"C.JAL": {},
}

var branchInsnMap = map[string]BranchInsnInfo{
	"BNE":    {IsBranch: true, IsConditionalBranch: true},
	"BEQZ":   {IsBranch: true, IsConditionalBranch: true},
	"C.BEQZ": {IsBranch: true, IsConditionalBranch: true},
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

	if !targetObj.HasSection(".debug_aranges") {
		logger.ShowErrorMsg(".debug_aranges section not found. You need to set -g option for build.\n")
		os.Exit(-1)
	}
	debug_aranges := targetObj.GetSectionBinByName(".debug_aranges")
	aranges := dwarf.ReadAranges(debug_aranges)

	if !targetObj.HasSection(".debug_line") {
		logger.ShowErrorMsg(".debug_line section not found. You need to set -g option for build.\n")
		os.Exit(-1)
	}
	debug_line := targetObj.GetSectionBinByName(".debug_line")
	offsetLineInfoMap := dwarf.ReadLineInfo(debug_line, targetObj)

	if !targetObj.HasSection(".debug_frame") {
		logger.ShowErrorMsg(".debug_frame section not found. You need to set -g option for build.\n")
		os.Exit(-1)
	}
	debug_frame := targetObj.GetSectionBinByName(".debug_frame")
	frameInfo := dwarf.ReadFrameInfo(debug_frame, ".debug_frame")

	if !targetObj.HasSection(".debug_info") {
		logger.ShowErrorMsg(".debug_info section not found. You need to set -g option for build.\n")
		os.Exit(-1)
	}
	debug_info := targetObj.GetSectionBinByName(".debug_info")
	dbgInfos := dwarf.ReadDebugInfo(aranges, frameInfo, debug_info, targetObj, offsetLineInfoMap)

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

	funcSliceMap := make(map[uint64]FuncSlice)
	funcInfos := targetObj.GetFuncsInfos()
	//var elfMainFuncInfo *elf.ElfFunctionInfo
	for _, elfFuncInfo := range funcInfos {
		if strings.HasPrefix(elfFuncInfo.Name, "__") {
			continue
		}
		/*
			if elfFuncInfo.Name == "main" {
				//logger.DLog("main function found\n")
				elfMainFuncInfo = &funcInfos[i]
				continue
			}
		*/
		if elfFuncInfo.Name != "is_even" {
			continue
		}
		loadAddr, err := targetObj.GetSectionLoadAddrByName(elfFuncInfo.SecName)
		if err != nil {
			logger.ShowErrorMsg("Failed to disassemble\n")
			os.Exit(-1)
		}

		fStart := elfFuncInfo.Addr - loadAddr
		fEnd := fStart + elfFuncInfo.Size
		logger.DLog("Disassemble Name:%s, Addr:0x%X, Offset:0x%X, Size:%d, SecName:%s, LoadAddr:0x%X\n", elfFuncInfo.Name, elfFuncInfo.Addr, fStart, elfFuncInfo.Size, elfFuncInfo.SecName, loadAddr)
		secBin := targetObj.GetSectionBinByName(elfFuncInfo.SecName)
		if secBin == nil {
			logger.ShowErrorMsg("Cannot find .text section\n")
			os.Exit(-1)
		}
		if elfFuncInfo.Size < 1 {
			logger.DLog("func '%s' size is 0\n", elfFuncInfo.Name)
			continue
		}
		fBin := secBin[fStart:fEnd]
		insns, err := cs.Disasm(fBin, elfFuncInfo.Addr, 0)
		if err != nil {
			logger.ShowErrorMsg("Failed to disassemble\n")
			os.Exit(-1)
		}
		// 引数・ローカル変数の情報を取得
		var dbgFunc *dwarf.Dwarf32FuncInfo = nil
		for _, dbgInfo := range dbgInfos {
			dbg_f, exist := dbgInfo.Funcs[elfFuncInfo.Addr]
			if !exist {
				continue
			}
			logger.DLog("Name:%s(%s), Addr:0x%0X, SrcFile:%s, FrameBase:%d\n", dbg_f.Name, dbg_f.LinkageName, dbg_f.Addr, dbg_f.SrcFilePath, dbg_f.FrameBase)

			logger.DLog("Args: %d\n", len(dbg_f.Args))
			for _, arg := range dbg_f.Args {
				logger.DLog("Name:%s, Location(Reg:%d, Offset:%d)\n", arg.Name, arg.Location.Reg, arg.Location.Offset)
			}

			logger.DLog("Local Vars: %d\n", len(dbg_f.LocalVars))
			for _, arg := range dbg_f.LocalVars {
				logger.DLog("Name:%s, Location(Reg:%d, Offset:%d)\n", arg.Name, arg.Location.Reg, arg.Location.Offset)
			}
			dbgFunc = &dbg_f
			break
		}

		funcSlice := backwardSlice(insns, &targetObj, dbgFunc)
		funcSliceMap[elfFuncInfo.Addr] = funcSlice
		basicBlk, exist := funcSlice.BasicBlks[elfFuncInfo.Addr]
		if exist {
			for _, relatedOperand := range basicBlk.RelatedOperands {
				logger.ShowErrorMsg("RegName:[%s], RegNum:[%d]\n", relatedOperand.RegName, relatedOperand.RegNum)
				if relatedOperand.HasValue {
					logger.ShowErrorMsg("LinkValue Type:[%d]\n", relatedOperand.LinkValueType)
				} else {
					logger.ShowErrorMsg("\n")
				}
			}
		} else {
			logger.DLog("%s entry block not found \n", elfFuncInfo.Name)
		}
	}

	// メイン関数の解析
	/*
		if elfMainFuncInfo != nil {
			loadAddr, err := targetObj.GetSectionLoadAddrByName(elfMainFuncInfo.SecName)
			if err != nil {
				logger.ShowErrorMsg("Failed to disassemble\n")
				os.Exit(-1)
			}

			fStart := elfMainFuncInfo.Addr - loadAddr
			fEnd := fStart + elfMainFuncInfo.Size
			logger.DLog("Disassemble Name:%s, Addr:0x%X, Offset:0x%X, Size:%d, SecName:%s, LoadAddr:0x%X\n", elfMainFuncInfo.Name, elfMainFuncInfo.Addr, fStart, elfMainFuncInfo.Size, elfMainFuncInfo.SecName, loadAddr)
			secBin := targetObj.GetSectionBinByName(elfMainFuncInfo.SecName)
			if secBin == nil {
				logger.ShowErrorMsg("Cannot find .text section\n")
				os.Exit(-1)
			}
			if 0 < elfMainFuncInfo.Size {
				fBin := secBin[fStart:fEnd]
				insns, err := cs.Disasm(fBin, elfMainFuncInfo.Addr, 0)
				if err != nil {
					logger.ShowErrorMsg("Failed to disassemble\n")
					os.Exit(-1)
				}

				funcSlice := backwardSlice(insns, &targetObj)
				funcSliceMap[elfMainFuncInfo.Addr] = funcSlice
				basicBlk, exist := funcSlice.BasicBlks[elfMainFuncInfo.Addr]
				if exist {
					num := len(basicBlk.RelatedOperands)
					logger.ShowErrorMsg("************ dump RelatedOperands:[%d] *******\n", num)
					for _, relatedOperand := range basicBlk.RelatedOperands {
						logger.ShowErrorMsg("RegName:[%s], RegNum:[%d]\n", relatedOperand.RegName, relatedOperand.RegNum)
						if relatedOperand.HasValue {
							logger.ShowErrorMsg("LinkValue Type:[%d]\n", relatedOperand.LinkValueType)
						} else {
							logger.ShowErrorMsg("\n")
						}
					}
				}
			}
		}
	*/
}

func backwardSlice(insns []capstone.Instruction, targetObj *elf.ElfObject, dbgInfo *dwarf.Dwarf32FuncInfo) (funcSlice FuncSlice) {
	basicBlks := make(map[uint64]BasicBlock)
	var curBasickBlk *BasicBlock

	// 基本ブロックの切り出し
	for _, insn := range insns {
		// le_bytes := reverse(insn.Bytes)
		//logger.ShowAppMsg("0x%x:\t%X\t%s\t%s, OpCount:%d\n", insn.Address, le_bytes, insn.Mnemonic, insn.OpStr, insn.Riscv.OpCount)
		if curBasickBlk == nil {
			curBasickBlk = &BasicBlock{
				EntryAddr:  uint64(insn.Address),
				From:       []uint64{},
				NextAddrs:  []uint64{},
				BranchInsn: nil,
				Insns:      []capstone.Instruction{},
			}
		}
		curBasickBlk.Insns = append(curBasickBlk.Insns, insn)

		// 引数・ローカル変数のチェック
		isLoadImm := isLoadMemInsn(&insn)
		if isLoadImm {
			for _, arg := range dbgInfo.Args {
				mem := insn.Riscv.Operands[1]
				if arg.Location.Reg == uint32(mem.Mem.Base) {
					if int64(arg.Location.Offset) == mem.Mem.Disp {
						logger.DLog("Arg Store Found!!!\n")
						//reg := insn.Riscv.Operands[0]
					}
				}
			}
		}

		//le_bytes := reverse(insn.Bytes)
		//logger.ShowAppMsg("**** branch found, 0x%x:\t%X\t%s\t%s, OpCount:%d\n", insn.Address, le_bytes, insn.Mnemonic, insn.OpStr, insn.Riscv.OpCount)
		isBransh, _ := isBranchInsn(&insn)
		if isBransh {
			curBasickBlk.BranchInsn = &insn
			jmpAddrs := getJmpAddrs(&insn)
			curBasickBlk.NextAddrs = append(curBasickBlk.NextAddrs, jmpAddrs...)
			basicBlks[curBasickBlk.EntryAddr] = *curBasickBlk
			curBasickBlk = nil
		}
	}
	if curBasickBlk != nil {
		basicBlks[curBasickBlk.EntryAddr] = *curBasickBlk
		curBasickBlk = nil
	}

	// 後ろ向きスライシング
	for entryAddr, basicBlk := range basicBlks {
		relatedOperands := make([]RiscVReg, 0)
		//logger.ShowAppMsg("**** entryAddr: 0x%X\n", entryAddr)
		revInsns := capstone.ReverseInsns(basicBlk.Insns)
		for _, insn := range revInsns {
			le_bytes := reverse(insn.Bytes)

			isBransh, _ := isBranchInsn(&insn)
			if isBransh {
				logger.DLog("Branch insn found, 0x%x:\t%X\t%s\t%s, OpCount:%d\n", insn.Address, le_bytes, insn.Mnemonic, insn.OpStr, insn.Riscv.OpCount)
				oprnds := getRelatedOperands(&insn)
				relatedOperands = append(relatedOperands, oprnds...)
				continue
			}
			isLoadImm := isLoadImmInsn(&insn)
			if isLoadImm {
				reg := insn.Riscv.Operands[0]
				imm := insn.Riscv.Operands[1]
				for i, relatedOperand := range relatedOperands {
					if relatedOperand.RegNum == reg.Reg {
						logger.DLog("Update relatedOperand by Load Imm, 0x%x:\t%X\t%s\t%s, OpCount:%d\n", insn.Address, le_bytes, insn.Mnemonic, insn.OpStr, insn.Riscv.OpCount)

						relatedOperands[i].HasValue = true
						relatedOperands[i].LinkValueType = LinkValueTypeImm // capstone.RISCV_OP_IMM
						relatedOperands[i].LinkValue = imm.Imm
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
					reg := insn.Riscv.Operands[0]
					mem := insn.Riscv.Operands[1]
					if relatedOperand.RegNum == reg.Reg {
						linkReg := RiscVMem{RegNum: mem.Mem.Base, Offset: mem.Mem.Disp, Value: 0, HasValue: false}
						regName := capstone.GetRiscVRegName(mem.Mem.Base)
						logger.ShowAppMsg("Load Related Reg found: [%s][%d], LinkMem:[%s][%d]\n", relatedOperand.RegName, relatedOperand.RegNum, regName, mem.Mem.Base)

						// 参照しているレジスタは使いまわしされる可能性があるので更新しておく
						relatedOperands[i].RegNum = mem.Mem.Base
						relatedOperands[i].HasValue = true
						relatedOperands[i].LinkValueType = LinkValueTypeMem
						relatedOperands[i].LinkMem = &linkReg
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

					// TODO: ここで依存するレジスタの内容を書き換えて問題ないか？
					if relatedOperand.LinkValueType == LinkValueTypeMem {
						// Update LinkMem to Reg
						logger.DLog("Update relatedOperand by store Insn , 0x%x:\t%X\t%s\t%s, OpCount:%d\n", insn.Address, le_bytes, insn.Mnemonic, insn.OpStr, insn.Riscv.OpCount)
						isSameBase := relatedOperand.LinkMem.RegNum == op1.Mem.Base
						isSameOffset := uint(relatedOperand.LinkMem.Offset) == uint(op1.Mem.Disp)
						if isSameBase && isSameOffset {
							regName := capstone.GetRiscVRegName(op0.Reg)
							logger.DLog("related reg:[%s] updated to reg:[%s], regNum:[%d]", relatedOperands[i].RegName, regName, op0.Reg)
							relatedOperands[i].HasValue = false
							relatedOperands[i].LinkValueType = LinkValueTypeNone
							relatedOperands[i].LinkMem = nil
							relatedOperands[i].RegName = regName
							relatedOperands[i].RegNum = op0.Reg
						}
					}
				}
			}
		}
		basicBlk.RelatedOperands = relatedOperands
		basicBlks[entryAddr] = basicBlk
	}
	funcSlice = FuncSlice{BasicBlks: basicBlks}
	return funcSlice
}

func isMvInsn(insn *capstone.Instruction) (isMv bool) {
	nm := strings.ToUpper(insn.Mnemonic)
	_, isMv = mvInsnMap[nm]
	return isMv
}

func isRetInsn(insn *capstone.Instruction) bool {
	nm := strings.ToUpper(insn.Mnemonic)
	if nm == "C.JR" {
		op := insn.Riscv.Operands[0]
		if op.Reg == capstone.RISCV_REG_X1 {
			return true
		}
	}
	if nm == "JALR" {
		return true
	}

	return false
}

func checkRegUpdate(insn *capstone.Instruction, dstReg uint) (hasUpdate bool) {
	hasUpdate = false
	nm := strings.ToUpper(insn.Mnemonic)
	if nm == "MV" || nm == "C.MV" {
		hasUpdate = true
		op0 := insn.Riscv.Operands[0]
		//op1 := insn.Riscv.Operands[1]
		if op0.Reg == dstReg {
			hasUpdate = true
		}
	}
	if nm == "MV" || nm == "C.MV" {
		hasUpdate = true
		//op := insn.Riscv.Operands[1]
		//regName := capstone.GetRiscVRegName(op.Reg)
	}
	if nm == "MV" || nm == "C.MV" {
		hasUpdate = true
		//op := insn.Riscv.Operands[1]
		//regName := capstone.GetRiscVRegName(op.Reg)
	}
	return hasUpdate
}

func isFuncCallInsn(insn *capstone.Instruction) (isFuncCall bool) {
	nm := strings.ToUpper(insn.Mnemonic)
	_, isFuncCall = fancCallInsnMap[nm]
	return isFuncCall
}

func getRelatedOperands(insn *capstone.Instruction) (relatedOperands []RiscVReg) {
	nm := strings.ToUpper(insn.Mnemonic)
	if nm == "BNE" {
		operand := insn.Riscv.Operands[0]
		reg0Num := operand.Reg
		reg0Name := capstone.GetRiscVRegName(operand.Reg)

		operand = insn.Riscv.Operands[1]
		reg1Num := operand.Reg
		reg1Name := capstone.GetRiscVRegName(operand.Reg)

		relatedOperands = append(relatedOperands, RiscVReg{RegNum: reg0Num, RegName: reg0Name, HasValue: false})
		relatedOperands = append(relatedOperands, RiscVReg{RegNum: reg1Num, RegName: reg1Name, HasValue: false})
	}
	if nm == "BEQZ" || nm == "C.BEQZ" {
		operand := insn.Riscv.Operands[0]
		reg0Num := operand.Reg
		reg0Name := capstone.GetRiscVRegName(operand.Reg)

		relatedOperands = append(relatedOperands, RiscVReg{RegNum: reg0Num, RegName: reg0Name, HasValue: false})
	}
	return relatedOperands
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
