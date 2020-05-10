package elf

// Section Stub
type Section struct {
	Data      []byte /* Actual bytes from the file */
	startAddr uint64 /* Where in memory the code starts */
	archBits  int    /* 32 or 64 bit */
}

// Disassembles data into readable instructions
func (s Section) Disassemble() string {
	dis := Disassembler{Buf: s.Data, StartAddr: s.startAddr, Arch: s.archBits}
	return dis.Disasm()
}
