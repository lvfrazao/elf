package elf

import "fmt"

// EICLASS
const (
	CLASS32BIT = 1 + iota /* 32 bit ELF */
	CLASS64BIT            /* 64 bit ELF */
)

// EIDATA
const (
	litteEndian = 1 + iota /* Little Endian */
	bigEndian              /* Big endian */
)

// ClassMap Maps EICLASS to friendly name
var ClassMap = map[uint8]string{
	CLASS32BIT: "32 bit",
	CLASS64BIT: "64 bit",
}

// DataMap Maps EIDATA to friendly name
var DataMap = map[uint8]string{
	litteEndian: "Little Endian",
	bigEndian:   "Big Endian",
}

var typeDesc = map[string]string{
	"ET_NONE":   "No file type",
	"ET_REL":    "Relocatable file",
	"ET_EXEC":   "Executable file",
	"ET_DYN":    "Shared object file",
	"ET_CORE":   "Core file",
	"ET_LOPROC": "Processor specific file",
	"ET_HIPROC": "Processor specific file",
}

// OSABIEncode map of friendly string to OSABI
var OSABIEncode = map[string]uint8{
	"System V":                     0x00,
	"HP-UX":                        0x01,
	"NetBSD":                       0x02,
	"Linux":                        0x03,
	"GNU Hurd":                     0x04,
	"Solaris":                      0x06,
	"AIX":                          0x07,
	"IRIX":                         0x08,
	"FreeBSD":                      0x09,
	"Tru64":                        0x0A,
	"Novell Modesto":               0x0B,
	"OpenBSD":                      0x0C,
	"OpenVMS":                      0x0D,
	"NonStop Kernel":               0x0E,
	"AROS":                         0x0F,
	"Fenix OS":                     0x10,
	"CloudABI":                     0x11,
	"Stratus Technologies OpenVOS": 0x12,
}

// OSABIDecode map of OSABI to friendly string
var OSABIDecode = map[uint8]string{
	0x00: "System V",
	0x01: "HP-UX",
	0x02: "NetBSD",
	0x03: "Linux",
	0x04: "GNU Hurd",
	0x06: "Solaris",
	0x07: "AIX",
	0x08: "IRIX",
	0x09: "FreeBSD",
	0x0A: "Tru64",
	0x0B: "Novell Modesto",
	0x0C: "OpenBSD",
	0x0D: "OpenVMS",
	0x0E: "NonStop Kernel",
	0x0F: "AROS",
	0x10: "Fenix OS",
	0x11: "CloudABI",
	0x12: "Stratus Technologies OpenVOS",
}

var etypeEncode = map[string]uint16{
	"ET_NONE":   0x00,
	"ET_REL":    0x01,
	"ET_EXEC":   0x02,
	"ET_DYN":    0x03,
	"ET_CORE":   0x04,
	"ET_LOOS":   0xfe00,
	"ET_HIOS":   0xfeff,
	"ET_LOPROC": 0xff00,
	"ET_HIPROC": 0xffff,
}

var etypeDecode = map[uint16]string{
	0x00:   "ET_NONE",
	0x01:   "ET_REL",
	0x02:   "ET_EXEC",
	0x03:   "ET_DYN",
	0x04:   "ET_CORE",
	0xfe00: "ET_LOOS",
	0xfeff: "ET_HIOS",
	0xff00: "ET_LOPROC",
	0xffff: "ET_HIPROC",
}

var emachineEncode = map[string]uint16{
	"None":    0x00,
	"SPARC":   0x02,
	"x86":     0x03,
	"MIPS":    0x08,
	"PowerPC": 0x14,
	"S390":    0x16,
	"ARM":     0x28,
	"SuperH":  0x2A,
	"IA-64":   0x32,
	"amd64":   0x3E,
	"AArch64": 0xB7,
	"RISC-V	": 0xF3,
}

var emachineDecode = map[uint16]string{
	0x00: "None",
	0x02: "SPARC",
	0x03: "x86",
	0x08: "MIPS",
	0x14: "PowerPC",
	0x16: "S390",
	0x28: "ARM",
	0x2A: "SuperH",
	0x32: "IA-64",
	0x3E: "amd64",
	0xB7: "AArch64",
	0xF3: "RISC-V",
}

// FileHeader64 64 bit ELF header
type FileHeader64 struct {
	EIMAG        uint32 /* Magic number, always 0x7F454C46 ("\x7fELF") */
	EICLASS      uint8  /* ELF Class 1 = 32bit, 2 = 64bit */
	EIDATA       uint8  /* Endianess 1 = little, 2 = big */
	EIVERSION    uint8  /* Always 1 */
	EIOSABI      uint8  /* Usually just set to 0 no matter what */
	EIABIVERSION uint8  /* Usually 0, sometimes not zero if EI_OSABI == 3 */
	EType        uint16 /* Identifies object file type - see etypeEncode */
	EMachine     uint16 /* Specifies ISA - see emachineEncode */
	EVersion     uint32 /* Set to 1 */
	EEntry       uint64 /* Addr of entry point of process */
	EPhoff       uint64 /* Pos of the program header table - usually 0x40 */
	EShoff       uint64 /* Pos of section header table */
	EFlags       uint32 /* Depends on arch */
	EEhsize      uint16 /* Size of this header, usually 64 bytes */
	EPhentsize   uint16 /* Size of a program header table entry */
	EPhnum       uint16 /* Number of entries in program header table */
	EShentsize   uint16 /* Size of a section header table entry */
	EShnum       uint16 /* Number of entries in section header table */
	EShstrndx    uint16 /* Index of section header table entry containing section names */
	OSABI        string /* Friendly name of EI_OSABI */
	Type         string /* Friendly name of E_type */
	TypeDesc     string /* Description of E_type */
	Machine      string /* Friendly name of E_machine */
	Endian       string /* Friendly name of EI_data */
	Arch         string /* Friendly name of EI_class */
}

// FileHeader32 32 bit ELF header
type FileHeader32 struct {
	EIMAG        uint32 /* Magic number, always 0x7F454C46 ("\x7fELF") */
	EICLASS      uint8  /* ELF Class 1 = 32bit, 2 = 64bit */
	EIDATA       uint8  /* Endianess 1 = little, 2 = big */
	EIVERSION    uint8  /* Always 1 */
	EIOSABI      uint8  /* Usually just set to 0 no matter what */
	EIABIVERSION uint8  /* Usually 0, sometimes not zero if EI_OSABI == 3 */
	EType        uint16 /* Identifies object file type - see etypeEncode */
	EMachine     uint16 /* Specifies ISA - see emachineEncode */
	EVersion     uint32 /* Set to 1 */
	EEntry       uint32 /* Addr of entry point of process */
	EPhoff       uint32 /* Pos of the program header table - usually 0x40 */
	EShoff       uint32 /* Pos of section header table */
	EFlags       uint32 /* Depends on arch */
	EEhsize      uint16 /* Size of this header, usually 64 bytes */
	EPhentsize   uint16 /* Size of a program header table entry */
	EPhnum       uint16 /* Number of entries in program header table */
	EShentsize   uint16 /* Size of a section header table entry */
	EShnum       uint16 /* Number of entries in section header table */
	EShstrndx    uint16 /* Index of section header table entry containing section names */
	OSABI        string /* Friendly name of EI_OSABI */
	Type         string /* Friendly name of E_type */
	TypeDesc     string /* Description of E_type */
	Machine      string /* Friendly name of E_machine */
	Endian       string /* Friendly name of EI_data */
	Arch         string /* Friendly name of EI_class */
}

// FromBuffer initializes the FileHeader64 given a buffer of the size of the
// file header
func (h *FileHeader64) FromBuffer(buf []byte) {
	h.EIMAG = readu32be(buf[:4], 0)
	assert(h.EIMAG == 0x7F454C46, "Magic number missing! Not an ELF!!")

	h.EICLASS = readu8(buf, 0x04)
	assert(h.EICLASS == CLASS64BIT, fmt.Sprintf("Wrong class type, EI_CLASS not 64 bit, actually 0x%X", h.EICLASS))

	h.EIDATA = readu8(buf, 0x05)
	h.EIVERSION = readu8(buf, 0x06)
	h.EIOSABI = readu8(buf, 0x07)
	h.EIABIVERSION = readu8(buf, 0x08)
	switch h.EIDATA {
	case bigEndian:
		h.EType = readu16be(buf, 0x10)
		h.EMachine = readu16be(buf, 0x12)
		h.EVersion = readu32be(buf, 0x14)
		h.EEntry = readu64be(buf, 0x18)
		h.EPhoff = readu64be(buf, 0x20)
		h.EShoff = readu64be(buf, 0x28)
		h.EFlags = readu32be(buf, 0x30)
		h.EEhsize = readu16be(buf, 0x34)
		h.EPhentsize = readu16be(buf, 0x36)
		h.EPhnum = readu16be(buf, 0x38)
		h.EShentsize = readu16be(buf, 0x3a)
		h.EShnum = readu16be(buf, 0x3c)
		h.EShstrndx = readu16be(buf, 0x3e)
	case litteEndian:
		h.EType = readu16le(buf, 0x10)
		h.EMachine = readu16le(buf, 0x12)
		h.EVersion = readu32le(buf, 0x14)
		h.EEntry = readu64le(buf, 0x18)
		h.EPhoff = readu64le(buf, 0x20)
		h.EShoff = readu64le(buf, 0x28)
		h.EFlags = readu32le(buf, 0x30)
		h.EEhsize = readu16le(buf, 0x34)
		h.EPhentsize = readu16le(buf, 0x36)
		h.EPhnum = readu16le(buf, 0x38)
		h.EShentsize = readu16le(buf, 0x3a)
		h.EShnum = readu16le(buf, 0x3c)
		h.EShstrndx = readu16le(buf, 0x3e)
	}
	h.OSABI = OSABIDecode[h.EIOSABI]
	h.Type = etypeDecode[h.EType]
	h.TypeDesc = typeDesc[h.Type]
	h.Machine = emachineDecode[h.EMachine]
	h.Endian = DataMap[h.EIDATA]
	h.Arch = ClassMap[h.EICLASS]
}

// FromBuffer initializes the FileHeader32 given a buffer of the size of the
// file header
func (h *FileHeader32) FromBuffer(buf []byte) {
	h.EIMAG = readu32be(buf[:4], 0)
	assert(h.EIMAG == 0x7F454C46, "Magic number missing! Not an ELF!!")

	h.EICLASS = readu8(buf, 0x04)
	assert(h.EICLASS == CLASS64BIT, fmt.Sprintf("Wrong class type, EI_CLASS not 64 bit, actually 0x%X", h.EICLASS))

	h.EIDATA = readu8(buf, 0x05)
	h.EIVERSION = readu8(buf, 0x06)
	h.EIOSABI = readu8(buf, 0x07)
	h.EIABIVERSION = readu8(buf, 0x08)
	switch h.EIDATA {
	case bigEndian:
		h.EType = readu16be(buf, 0x10)
		h.EMachine = readu16be(buf, 0x12)
		h.EVersion = readu32be(buf, 0x14)
		h.EEntry = readu32be(buf, 0x18)
		h.EPhoff = readu32be(buf, 0x1C)
		h.EShoff = readu32be(buf, 0x20)
		h.EFlags = readu32be(buf, 0x24)
		h.EEhsize = readu16be(buf, 0x28)
		h.EPhentsize = readu16be(buf, 0x2A)
		h.EPhnum = readu16be(buf, 0x2C)
		h.EShentsize = readu16be(buf, 0x2E)
		h.EShnum = readu16be(buf, 0x30)
		h.EShstrndx = readu16be(buf, 0x32)
	case litteEndian:
		h.EType = readu16le(buf, 0x10)
		h.EMachine = readu16le(buf, 0x12)
		h.EVersion = readu32le(buf, 0x14)
		h.EEntry = readu32le(buf, 0x18)
		h.EPhoff = readu32le(buf, 0x1C)
		h.EShoff = readu32le(buf, 0x20)
		h.EFlags = readu32le(buf, 0x24)
		h.EEhsize = readu16le(buf, 0x28)
		h.EPhentsize = readu16le(buf, 0x2A)
		h.EPhnum = readu16le(buf, 0x2C)
		h.EShentsize = readu16le(buf, 0x2E)
		h.EShnum = readu16le(buf, 0x30)
		h.EShstrndx = readu16le(buf, 0x32)
	}
	h.OSABI = OSABIDecode[h.EIOSABI]
	h.Type = etypeDecode[h.EType]
	h.TypeDesc = typeDesc[h.Type]
	h.Machine = emachineDecode[h.EMachine]
	h.Endian = DataMap[h.EIDATA]
	h.Arch = ClassMap[h.EICLASS]
}
