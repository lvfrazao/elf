package elf

import "fmt"

// PTypeDecode map of PType to friendly string
var PTypeDecode = map[uint32]string{
	0x00000000: "PT_NULL",
	0x00000001: "PT_LOAD",
	0x00000002: "PT_DYNAMIC",
	0x00000003: "PT_INTERP",
	0x00000004: "PT_NOTE",
	0x00000005: "PT_SHLIB",
	0x00000006: "PT_PHDR",
	0x00000007: "PT_TLS",
	0x60000000: "PT_LOOS",
	0x6FFFFFFF: "PT_HIOS",
	0x70000000: "PT_LOPROC",
	0x7FFFFFFF: "PT_HIPROC",
}

// PTypeEncode map of friendly string to PType
var PTypeEncode = map[string]uint32{
	"PT_NULL":    0x00000000,
	"PT_LOAD":    0x00000001,
	"PT_DYNAMIC": 0x00000002,
	"PT_INTERP":  0x00000003,
	"PT_NOTE":    0x00000004,
	"PT_SHLIB":   0x00000005,
	"PT_PHDR":    0x00000006,
	"PT_TLS":     0x00000007,
	"PT_LOOS":    0x60000000,
	"PT_HIOS":    0x6FFFFFFF,
	"PT_LOPROC":  0x70000000,
	"PT_HIPROC":  0x7FFFFFFF,
}

var flagsDecode = map[uint32]string{
	0x0: "NULL",
	0x1: "EXECUTE",
	0x2: "WRITE",
	0x4: "READ",
}

var flagsEncode = map[string]uint32{
	"NULL":    0x0,
	"EXECUTE": 0x1,
	"WRITE":   0x2,
	"READ":    0x4,
}

// ProgramHeader64 64 bit program header struct
type ProgramHeader64 struct {
	PType       uint32   /* Identifies the type of the segment. */
	PFlags      uint32   /* Segment-dependent flags (position for 64-bit structure). */
	POffset     uint64   /* Offset of the segment in the file image. */
	PVaddr      uint64   /* Virtual address of the segment in memory. */
	PPaddr      uint64   /* On systems where physical address is relevant, reserved for segment's physical address. */
	PFilesz     uint64   /* Size in bytes of the segment in the file image. May be 0. */
	PMemsz      uint64   /* Size in bytes of the segment in memory. May be 0. */
	PAlign      uint64   /* 0 and 1 specify no alignment. Otherwise should be power of 2 */
	SegmentType string   /* Pretty name for the PType */
	Flags       []string /* Flag friend names */
	FileOffset  uint64   /* Offset of header in the file */
}

// FromBuffer given a sufficiently sized, filled, buffer initialize the attrs of the ProgramHeader64
func (h *ProgramHeader64) FromBuffer(buf []byte, endianess uint8) {
	u32 := readu32Func(endianess)
	u64 := readu64Func(endianess)

	h.PType = u32(buf, 0x00)
	h.PFlags = u32(buf, 0x04)
	h.POffset = u64(buf, 0x08)
	h.PVaddr = u64(buf, 0x10)
	h.PPaddr = u64(buf, 0x18)
	h.PFilesz = u64(buf, 0x20)
	h.PMemsz = u64(buf, 0x28)
	h.SegmentType = PTypeDecode[h.PType]
	h.readFlags()
}

func (h *ProgramHeader64) readFlags() {
	if h.PFlags == 0 {
		h.Flags = make([]string, 1)
		h.Flags[0] = flagsDecode[0]
		return
	}
	h.Flags = make([]string, 0, 32)
	for i := 0; i < 32; i++ {
		var bitmask uint32 = 1 << i
		present := (h.PFlags & bitmask) != 0
		if present {
			flagStr := flagsDecode[bitmask]
			if flagStr == "" {
				flagStr = fmt.Sprintf("0x%X", bitmask)
			}
			h.Flags = append(h.Flags, flagStr)
		}
	}
}
