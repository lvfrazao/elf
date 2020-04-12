package elf

import "fmt"

// SHTypeDecode map decoding uint32 values into firendly strings
var SHTypeDecode = map[uint32]string{
	0x0:        "SHT_NULL",          /* Section header table entry unused */
	0x1:        "SHT_PROGBITS",      /* Program data */
	0x2:        "SHT_SYMTAB",        /* Symbol table */
	0x3:        "SHT_STRTAB",        /* String table */
	0x4:        "SHT_RELA",          /* Relocation entries with addends */
	0x5:        "SHT_HASH",          /* Symbol hash table */
	0x6:        "SHT_DYNAMIC",       /* Dynamic linking information */
	0x7:        "SHT_NOTE",          /* Notes */
	0x8:        "SHT_NOBITS",        /* Program space with no data (bss) */
	0x9:        "SHT_REL",           /* Relocation entries, no addends */
	0x0A:       "SHT_SHLIB",         /* Reserved */
	0x0B:       "SHT_DYNSYM",        /* Dynamic linker symbol table */
	0x0E:       "SHT_INIT_ARRAY",    /* Array of constructors */
	0x0F:       "SHT_FINI_ARRAY",    /* Array of destructors */
	0x10:       "SHT_PREINIT_ARRAY", /* Array of pre-constructors */
	0x11:       "SHT_GROUP",         /* Section group */
	0x12:       "SHT_SYMTAB_SHNDX",  /* Extended section indices */
	0x13:       "SHT_NUM",           /* Number of defined types. */
	0x60000000: "SHT_LOOS",          /* Start OS-specific. */
}

// SHTypeEncode encodes friendly shtype strings to uint32 value
var SHTypeEncode = map[string]uint32{
	"SHT_NULL":          0x0,
	"SHT_PROGBITS":      0x1,
	"SHT_SYMTAB":        0x2,
	"SHT_STRTAB":        0x3,
	"SHT_RELA":          0x4,
	"SHT_HASH":          0x5,
	"SHT_DYNAMIC":       0x6,
	"SHT_NOTE":          0x7,
	"SHT_NOBITS":        0x8,
	"SHT_REL":           0x9,
	"SHT_SHLIB":         0x0A,
	"SHT_DYNSYM":        0x0B,
	"SHT_INIT_ARRAY":    0x0E,
	"SHT_FINI_ARRAY":    0x0F,
	"SHT_PREINIT_ARRAY": 0x10,
	"SHT_GROUP":         0x11,
	"SHT_SYMTAB_SHNDX":  0x12,
	"SHT_NUM":           0x13,
	"SHT_LOOS":          0x60000000,
}

// SHFlagsDecode maps uint64 to friendly name for shflags
var SHFlagsDecode = map[uint64]string{
	0x0:        "NULL",
	0x1:        "SHF_WRITE",            /* Writable */
	0x2:        "SHF_ALLOC",            /* Occupies memory during execution */
	0x4:        "SHF_EXECINSTR",        /* Executable */
	0x10:       "SHF_MERGE",            /* Might be merged */
	0x20:       "SHF_STRINGS",          /* Contains nul-terminated strings */
	0x40:       "SHF_INFO_LINK",        /* 'sh_info' contains SHT index */
	0x80:       "SHF_LINK_ORDER",       /* Preserve order after combining */
	0x100:      "SHF_OS_NONCONFORMING", /* Non-standard OS specific handling required */
	0x200:      "SHF_GROUP",            /* Section is member of a group */
	0x400:      "SHF_TLS",              /* Section hold thread-local data */
	0x0ff00000: "SHF_MASKOS",           /* OS-specific */
	0xf0000000: "SHF_MASKPROC",         /* Processor-specific */
	0x4000000:  "SHF_ORDERED",          /* Special ordering requirement (Solaris) */
	0x8000000:  "SHF_EXCLUDE",          /* Section is excluded unless referenced or allocated (Solaris)	 */
}

// SHFlagsEncode maps friendly name to uint64 for shflags
var SHFlagsEncode = map[string]uint64{
	"NULL":                 0x0,
	"SHF_WRITE":            0x1,
	"SHF_ALLOC":            0x2,
	"SHF_EXECINSTR":        0x4,
	"SHF_MERGE":            0x10,
	"SHF_STRINGS":          0x20,
	"SHF_INFO_LINK":        0x40,
	"SHF_LINK_ORDER":       0x80,
	"SHF_OS_NONCONFORMING": 0x100,
	"SHF_GROUP":            0x200,
	"SHF_TLS":              0x400,
	"SHF_MASKOS":           0x0ff00000,
	"SHF_MASKPROC":         0xf0000000,
	"SHF_ORDERED":          0x4000000,
	"SHF_EXCLUDE":          0x8000000,
}

// SectionHeader64 section header struct
type SectionHeader64 struct {
	SHName       uint32   /* index of shstrtab string - name */
	SHType       uint32   /* Identifies the type of this header. */
	SHFlags      uint64   /* Identifies the attributes of the section. */
	SHAddr       uint64   /* Virtual address of the section in memory. */
	SHOffset     uint64   /* Offset of the section in the file image. */
	SHSize       uint64   /* Size in bytes of the section in the file image. */
	SHLink       uint32   /* Section index of an associated section. */
	SHInfo       uint32   /* Extra information about the section. */
	SHAddrAlign  uint64   /* Required alignment of the section. */
	SHEntsize    uint64   /* Size, in bytes, of each entry */
	HeaderType   string   /* Friendly name for shtype */
	SectionFlags []string /* Friendly name for section flag */
	SectionName  string   /* Name of section */
}

// FromBuffer initializes the SectionHeader64 given a buffer of the size of the
// section header
func (h *SectionHeader64) FromBuffer(buf []byte, endianess uint8) {
	u32 := readu32Func(endianess)
	u64 := readu64Func(endianess)

	h.SHName = u32(buf, 0x00)
	h.SHType = u32(buf, 0x04)
	h.SHFlags = u64(buf, 0x08)
	h.SHAddr = u64(buf, 0x10)
	h.SHOffset = u64(buf, 0x18)
	h.SHSize = u64(buf, 0x20)
	h.SHLink = u32(buf, 0x28)
	h.SHInfo = u32(buf, 0x2C)
	h.SHAddrAlign = u64(buf, 0x30)
	h.SHEntsize = u64(buf, 0x38)
	h.HeaderType = SHTypeDecode[h.SHType]
	h.readFlags()
}

func (h *SectionHeader64) readFlags() {
	if h.SHFlags == 0 {
		h.SectionFlags = make([]string, 1)
		h.SectionFlags[0] = SHFlagsDecode[0]
		return
	}
	h.SectionFlags = make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		var bitmask uint64 = 1 << i
		present := (h.SHFlags & bitmask) != 0
		if present {
			flagStr := SHFlagsDecode[bitmask]
			if flagStr == "" {
				flagStr = fmt.Sprintf("0x%X", bitmask)
			}
			h.SectionFlags = append(h.SectionFlags, flagStr)
		}
	}
}
