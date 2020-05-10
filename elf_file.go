package elf

// ELF64 format
type ELF64 struct {
	FileHeader     FileHeader64
	ProgramHeaders []ProgramHeader64
	Sections       []Section
	SectionHeaders []SectionHeader64
}
