package main

import (
	capstone "branch-walker/capstone"
	elf "branch-walker/elf"
	logger "branch-walker/logger"
	"fmt"
	"os"
	"path/filepath"
)

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
			load_addr, err := targetObj.GetSectionLoadAddrByName(elfFuncInfo.SecName)
			if err != nil {
				logger.ShowErrorMsg("Failed to disassemble\n")
				os.Exit(-1)
			}

			f_start := elfFuncInfo.Addr - load_addr
			f_end := f_start + elfFuncInfo.Size
			logger.DLog("Disassemble Name:%s, Addr:0x%X, Offset:0x%X, Size:%d, SecName:%s, LoadAddr:0x%X\n", elfFuncInfo.Name, elfFuncInfo.Addr, f_start, elfFuncInfo.Size, elfFuncInfo.SecName, load_addr)
			secBin := targetObj.GetSectionBinByName(elfFuncInfo.SecName)
			if secBin == nil {
				logger.ShowErrorMsg("Cannot find .text section\n")
				os.Exit(-1)
			}
			if elfFuncInfo.Size < 1 {
				logger.DLog("func '%s' size is 0\n", elfFuncInfo.Name)
				continue
			}
			f_bin := secBin[f_start:f_end]
			insns, err := cs.Disasm(f_bin, f_start, 0)
			if err != nil {
				logger.ShowErrorMsg("Failed to disassemble\n")
				os.Exit(-1)
			}
			//rev_insns := ReverseInsns(insns);
			for _, insn := range insns {
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
			}
		}
	}
}
