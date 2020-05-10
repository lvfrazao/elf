package elf

import (
	"fmt"
	"os"
	"strings"

	"github.com/knightsc/gapstone"
)

var archBitMap = map[int]int{
	32: int(gapstone.CS_MODE_32),
	64: int(gapstone.CS_MODE_64),
}

// Disassembler provides methods for disassembling executable code held in buffer
type Disassembler struct {
	Buf       []byte
	StartAddr uint64 /* Starting addr of first instruction */
	Arch      int    /* Either 32 or 64 */
}

// Disasm disassembly instructions in buffer
func (d Disassembler) Disasm() string {
	var disassembled string
	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		archBitMap[d.Arch],
	)
	defer engine.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting disassembler; %s", err)
		return disassembled
	}

	instructions, err := engine.Disasm(
		d.Buf,
		d.StartAddr,
		0,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error disassembling instructions; %s", err)
		return disassembled
	}

	var b strings.Builder
	for _, instr := range instructions {
		fmt.Fprintf(&b, "0x%x:\t% 29x\t\t%s\t\t%s\n", instr.Address, instr.Bytes, instr.Mnemonic, instr.OpStr)
	}
	disassembled = b.String()
	return disassembled
}
