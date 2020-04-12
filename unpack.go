package elf

import (
	"encoding/binary"
	"fmt"
	"os"
)

func checkedRead(f *os.File, buf []byte, offset int64) {
	_, err := f.ReadAt(buf, offset)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

func readStr(file *os.File, offset int) string {
	buf := make([]byte, 1)
	var name string
	// I'd rather not rely on finding a nul byte, but this seems to be the only way
	for i := 0; ; i++ {
		checkedRead(file, buf, int64(offset+i))
		if buf[0] == 0 {
			break
		}
		name += string(buf[0])
	}
	return name
}

func readu8(buf []byte, offset int) uint8 {
	return uint8(buf[offset])
}

func readu16Func(endianess uint8) func(buf []byte, offset int) uint16 {
	if endianess == litteEndian {
		return readu16le
	}
	return readu16be
}

func readu32Func(endianess uint8) func(buf []byte, offset int) uint32 {
	if endianess == litteEndian {
		return readu32le
	}
	return readu32be
}

func readu64Func(endianess uint8) func(buf []byte, offset int) uint64 {
	if endianess == litteEndian {
		return readu64le
	}
	return readu64be
}

func readu16le(buf []byte, offset int) uint16 {
	return binary.LittleEndian.Uint16(buf[offset : offset+2])
}

func readu32le(buf []byte, offset int) uint32 {
	return binary.LittleEndian.Uint32(buf[offset : offset+4])
}

func readu64le(buf []byte, offset int) uint64 {
	return binary.LittleEndian.Uint64(buf[offset : offset+8])
}

func readu16be(buf []byte, offset int) uint16 {
	return binary.BigEndian.Uint16(buf[offset : offset+2])
}

func readu32be(buf []byte, offset int) uint32 {
	return binary.BigEndian.Uint32(buf[offset : offset+4])
}

func readu64be(buf []byte, offset int) uint64 {
	return binary.BigEndian.Uint64(buf[offset : offset+8])
}
