package elf

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	pageSize = 0x1000
)

func Exec(code []byte) {
	codeAddr := &(code[0])
	size := len(code)

	err := makeExecutable(codeAddr, size)
	if err != 0 {
		fmt.Fprintf(os.Stderr, "Error with mprotect: %s\n", err)
	}

	codePtr := unsafe.Pointer(codeAddr)
	funcClosure := unsafe.Pointer(&codePtr)

	// A function is a pointer to a pointer to the code
	// So a function pointer needs to be a pointer to that
	// See: https://docs.google.com/document/d/1bMwCey-gmqZVTpRax-ESeVuZGmjwbocYs1iHplK-cjo/pub
	f := (*func())(unsafe.Pointer(&funcClosure))
	(*f)()
}

func makeExecutable(arbCode *byte, baseSize int) int {
	page := uintptr(unsafe.Pointer(arbCode)) & (^uintptr(0xFFF)) // The addr needs to be on a page boundary
	size := getSize(baseSize)                                    // The size needs to be a multiple of the page size
	if (uintptr(unsafe.Pointer(arbCode)) + uintptr(baseSize)) > (page + uintptr(size)) {
		size += pageSize
	}
	prot := syscall.PROT_READ | syscall.PROT_EXEC | syscall.PROT_WRITE
	_, _, err := syscall.Syscall(syscall.SYS_MPROTECT, page, size, uintptr(prot))
	return int(err)
}

func getSize(baseSize int) uintptr {
	// Rounds up to the closest pageSize (0x1000)
	return uintptr(baseSize + (pageSize - (baseSize % pageSize)))
}
