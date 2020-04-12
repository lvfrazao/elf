package elf

import (
	"fmt"
	"os"
)

const (
	fileHeader64Size = 0x40
	fileHeader32Size = 0x34
)

// Reader64 Provides functions for population ELF structs from a filename
type Reader64 struct {
	FileName  string // Name of ELF file
	filePtr   *os.File
	elfStruct ELF64
}

// FromFile Initializes an Reader struct from the filename
func (e *Reader64) FromFile(string) ELF64 {
	e.openFile()
	e.elfStruct.FileHeader = e.readFileHead64()
	e.elfStruct.ProgramHeaders = e.readProgramHeaders64()
	e.elfStruct.SectionHeaders = e.readSectionHeaders64()
	return e.elfStruct
}

func (e *Reader64) openFile() {
	program := e.FileName
	file, err := os.Open(program)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
	if e.checkClass(file) != CLASS64BIT {
		fmt.Fprint(os.Stderr, "Only 64 bit ELF supported\n")
		os.Exit(1)
	}
	e.filePtr = file
}

func (e *Reader64) checkClass(f *os.File) uint8 {
	b := make([]byte, 1)
	checkedRead(f, b, 0x04)
	return uint8(b[0])
}

func (e *Reader64) readFileHead64() FileHeader64 {
	readBuf := make([]byte, fileHeader64Size)
	checkedRead(e.filePtr, readBuf, 0x00)

	var h FileHeader64
	h.FromBuffer(readBuf)
	return h
}

func (e *Reader64) readProgramHeaders64() []ProgramHeader64 {
	pHead := make([]ProgramHeader64, int(e.elfStruct.FileHeader.EPhnum))
	for i := 0; i < int(e.elfStruct.FileHeader.EPhnum); i++ {
		offset := e.elfStruct.FileHeader.EPhoff + uint64(int(e.elfStruct.FileHeader.EPhentsize)*i)
		pHead[i] = e.readProgramHeader64(offset)
	}
	return pHead
}

func (e *Reader64) readProgramHeader64(offset uint64) ProgramHeader64 {
	var h ProgramHeader64
	if e.elfStruct.FileHeader.EPhentsize == 0 {
		return h
	}
	readBuf := make([]byte, e.elfStruct.FileHeader.EPhentsize)
	checkedRead(e.filePtr, readBuf, int64(offset))

	h.FromBuffer(readBuf, e.elfStruct.FileHeader.EIDATA)
	return h
}

func (e *Reader64) readSectionHeaders64() []SectionHeader64 {
	sHead := make([]SectionHeader64, int(e.elfStruct.FileHeader.EShnum))
	for i := 0; i < int(e.elfStruct.FileHeader.EShnum); i++ {
		offset := e.elfStruct.FileHeader.EShoff + uint64(int(e.elfStruct.FileHeader.EShentsize)*i)
		sHead[i] = e.readSectionHead64(offset)
	}

	if e.elfStruct.FileHeader.EShnum != 0 {
		nameDataOffset := sHead[e.elfStruct.FileHeader.EShstrndx].SHOffset
		for _, section := range sHead {
			section.SectionName = readStr(e.filePtr, int(nameDataOffset+uint64(section.SHName)))
		}
	}

	return sHead
}

func (e *Reader64) readSectionHead64(offset uint64) SectionHeader64 {
	readBuf := make([]byte, e.elfStruct.FileHeader.EShentsize)
	checkedRead(e.filePtr, readBuf, int64(offset))
	var h SectionHeader64
	h.FromBuffer(readBuf, e.elfStruct.FileHeader.EIDATA)
	return h
}
